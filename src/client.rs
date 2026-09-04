//! The client, and the one place a request is built, sent and judged.

use std::time::Duration;

use reqwest::{header, Method, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{ApiError, Error, Result};
use crate::types::{AnalyzeRequest, Collection, Declaration, Envelope, Job, Subject};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEFAULT_BASE_URL: &str = "https://ironeye.org";
const RETRYABLE_STATUS: &[u16] = &[408, 425, 429, 500, 502, 503, 504];

/// Builds a [`Client`]. The key comes from [`Builder::api_key`] or from
/// `IRONEYE_API_KEY`; the base URL from [`Builder::base_url`],
/// `IRONEYE_BASE_URL`, or the public host.
#[derive(Debug, Default)]
pub struct Builder {
    api_key: Option<String>,
    base_url: Option<String>,
    timeout: Option<Duration>,
    max_retries: Option<u32>,
}

impl Builder {
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    pub fn build(self) -> Result<Client> {
        let api_key = self
            .api_key
            .or_else(|| std::env::var("IRONEYE_API_KEY").ok())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| {
                Error::Config(
                    "an API key is required: use Builder::api_key or set IRONEYE_API_KEY".into(),
                )
            })?;
        let base_url = self
            .base_url
            .or_else(|| std::env::var("IRONEYE_BASE_URL").ok())
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let timeout = self.timeout.unwrap_or(Duration::from_secs(60));
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(format!("ironeye-rust/{VERSION}"))
            .build()?;
        Ok(Client {
            http,
            api_key,
            base_url: base_url.trim_end_matches('/').to_string(),
            max_retries: self.max_retries.unwrap_or(2),
        })
    }
}

/// The IronEye client. Cheap to clone: the inner `reqwest::Client` is an `Arc`
/// over one connection pool.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    api_key: String,
    base_url: String,
    max_retries: u32,
}

impl Client {
    /// A client from the environment alone.
    pub fn from_env() -> Result<Self> {
        Builder::default().build()
    }

    pub fn builder() -> Builder {
        Builder::default()
    }

    // -- analysis ----------------------------------------------------------
    pub async fn analyze(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/analyze", request).await
    }
    pub async fn extract(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/extract", request).await
    }
    pub async fn classify(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/classify", request).await
    }
    pub async fn pii(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/pii/analyze", request).await
    }
    pub async fn moderation(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/moderation/analyze", request).await
    }
    pub async fn malware(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/malware/scan", request).await
    }
    pub async fn secrets(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/secrets/scan", request).await
    }
    pub async fn validate(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/validate", request).await
    }
    pub async fn deduplicate(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/deduplicate", request).await
    }
    pub async fn invoices(&self, request: &AnalyzeRequest) -> Result<Envelope> {
        self.analysis("/v1/invoices/parse", request).await
    }

    async fn analysis(&self, path: &str, request: &AnalyzeRequest) -> Result<Envelope> {
        self.send(Method::POST, path, |builder| builder.json(request)).await
    }

    /// The same analysis, keyed so a repeat returns the first answer instead of
    /// running the engine twice.
    pub async fn analyze_idempotent(
        &self,
        request: &AnalyzeRequest,
        key: &str,
    ) -> Result<Envelope> {
        let key = key.to_string();
        self.send(Method::POST, "/v1/analyze", move |builder| {
            builder.header("Idempotency-Key", key.clone()).json(request)
        })
        .await
    }

    /// Multipart, for bytes you hold already rather than base64 in a body.
    pub async fn analyze_upload(
        &self,
        file: Vec<u8>,
        filename: &str,
        preset: Option<&str>,
    ) -> Result<Envelope> {
        let filename = filename.to_string();
        let preset = preset.map(str::to_string);
        self.send(Method::POST, "/v1/analyze/upload", move |builder| {
            let part = reqwest::multipart::Part::bytes(file.clone()).file_name(filename.clone());
            let mut form = reqwest::multipart::Form::new().part("file", part);
            if let Some(preset) = &preset {
                form = form.text("preset", preset.clone());
            }
            builder.multipart(form)
        })
        .await
    }

    // -- jobs --------------------------------------------------------------
    pub async fn create_job(&self, request: &AnalyzeRequest) -> Result<Job> {
        self.send(Method::POST, "/v1/jobs", |builder| builder.json(request)).await
    }

    pub async fn job(&self, job_id: &str) -> Result<Job> {
        self.send(Method::GET, &format!("/v1/jobs/{job_id}"), |builder| builder).await
    }

    pub async fn delete_job(&self, job_id: &str) -> Result<()> {
        self.send_empty(Method::DELETE, &format!("/v1/jobs/{job_id}")).await
    }

    /// Polls until the job settles. Nothing in the service dispatches to a
    /// callback URL, so polling is the whole asynchronous contract.
    pub async fn await_job(
        &self,
        job_id: &str,
        interval: Duration,
        limit: Duration,
    ) -> Result<Job> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let job = self.job(job_id).await?;
            if job.done() {
                return Ok(job);
            }
            if tokio::time::Instant::now() + interval > deadline {
                return Err(Error::JobTimeout { job_id: job.id, status: job.status });
            }
            tokio::time::sleep(interval).await;
        }
    }

    // -- collection --------------------------------------------------------
    pub async fn catalogue(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/harvest/catalogue", |builder| builder).await
    }

    pub async fn operations(&self, platform: Option<&str>) -> Result<Value> {
        let platform = platform.map(str::to_string);
        self.send(Method::GET, "/v1/harvest/operations", move |builder| match &platform {
            Some(platform) => builder.query(&[("platform", platform)]),
            None => builder,
        })
        .await
    }

    pub async fn operation(&self, op_id: &str) -> Result<Value> {
        self.send(Method::GET, &format!("/v1/harvest/operations/{op_id}"), |builder| builder).await
    }

    /// Runs one operation, addressed by its own route as the catalogue gives
    /// it: `/v1/harvest/reddit/subreddit`, say.
    pub async fn collect(
        &self,
        path: &str,
        params: &[(&str, &str)],
        declaration: &Declaration,
    ) -> Result<Collection> {
        let params: Vec<(String, String)> =
            params.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect();
        let headers = declaration.headers();
        self.send(Method::GET, path, move |mut builder| {
            for (name, value) in &headers {
                builder = builder.header(*name, value.clone());
            }
            builder.query(&params)
        })
        .await
    }

    /// `collect` for the operations the registry declares as POST. The
    /// parameters are identical; only where they travel changes.
    pub async fn collect_post(
        &self,
        path: &str,
        params: &[(&str, &str)],
        declaration: &Declaration,
    ) -> Result<Collection> {
        let body: serde_json::Map<String, Value> =
            params.iter().map(|(k, v)| ((*k).to_string(), Value::String((*v).into()))).collect();
        let headers = declaration.headers();
        self.send(Method::POST, path, move |mut builder| {
            for (name, value) in &headers {
                builder = builder.header(*name, value.clone());
            }
            builder.json(&body)
        })
        .await
    }

    // -- data subject rights ----------------------------------------------
    pub async fn gdpr_notice(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/gdpr/notice", |builder| builder).await
    }

    pub async fn erasure(&self, subject: &Subject) -> Result<Value> {
        self.send(Method::POST, "/v1/gdpr/erasure", |builder| builder.json(subject)).await
    }

    pub async fn objection(&self, subject: &Subject) -> Result<Value> {
        self.send(Method::POST, "/v1/gdpr/objections", |builder| builder.json(subject)).await
    }

    pub async fn access_request(&self, subject: &Subject) -> Result<Value> {
        self.send(Method::POST, "/v1/gdpr/access", |builder| builder.json(subject)).await
    }

    pub async fn suppression(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/gdpr/suppression", |builder| builder).await
    }

    pub async fn unsuppress(&self, subject_key: &str) -> Result<()> {
        self.send_empty(Method::DELETE, &format!("/v1/gdpr/suppression/{subject_key}")).await
    }

    // -- service -----------------------------------------------------------
    pub async fn health(&self) -> Result<Value> {
        self.send(Method::GET, "/healthz", |builder| builder).await
    }

    pub async fn ready(&self) -> Result<Value> {
        self.send(Method::GET, "/readyz", |builder| builder).await
    }

    pub async fn features(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/features", |builder| builder).await
    }

    pub async fn status(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/status", |builder| builder).await
    }

    pub async fn audit_head(&self) -> Result<Value> {
        self.send(Method::GET, "/v1/audit/head", |builder| builder).await
    }

    // -- transport ---------------------------------------------------------
    /// `decorate` runs once per attempt rather than once per call: a
    /// `RequestBuilder` is consumed when it is sent, so a retry needs a new one.
    async fn send<T, F>(&self, method: Method, path: &str, decorate: F) -> Result<T>
    where
        T: DeserializeOwned,
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let body = self.attempt(method, path, decorate).await?;
        Ok(serde_json::from_slice(&body)?)
    }

    async fn send_empty(&self, method: Method, path: &str) -> Result<()> {
        self.attempt(method, path, |builder| builder).await.map(|_| ())
    }

    async fn attempt<F>(&self, method: Method, path: &str, decorate: F) -> Result<Vec<u8>>
    where
        F: Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut last: Option<Error> = None;
        for attempt in 0..=self.max_retries {
            let builder = decorate(
                self.http
                    .request(method.clone(), &url)
                    .header(header::ACCEPT, "application/json")
                    .bearer_auth(&self.api_key),
            );
            let started = std::time::Instant::now();
            let response = match builder.send().await {
                Ok(response) => response,
                Err(transport) => {
                    if attempt == self.max_retries {
                        return Err(Error::Transport(transport));
                    }
                    tracing::warn!(path, error = %transport, "ironeye request failed, retrying");
                    last = Some(Error::Transport(transport));
                    self.backoff(attempt, None).await;
                    continue;
                }
            };

            let status = response.status();
            tracing::debug!(
                %method,
                path,
                status = status.as_u16(),
                duration_ms = started.elapsed().as_millis() as u64,
                request_id = response
                    .headers()
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("-"),
                "ironeye request"
            );
            let retry_after = header_seconds(&response, header::RETRY_AFTER);
            if status.is_success() {
                return Ok(response.bytes().await?.to_vec());
            }

            let error = api_error(status, response).await;
            let retryable = error.retryable && RETRYABLE_STATUS.contains(&status.as_u16());
            if attempt == self.max_retries || !retryable {
                return Err(Error::Api(Box::new(error)));
            }
            tracing::warn!(path, code = %error.code, "ironeye refused, retrying");
            last = Some(Error::Api(Box::new(error)));
            self.backoff(attempt, retry_after).await;
        }
        Err(last.unwrap_or_else(|| Error::Config("the request exhausted its retries".into())))
    }

    /// Retry-After is the server's own number, so it wins over the curve.
    async fn backoff(&self, attempt: u32, retry_after: Option<u64>) {
        let wait = match retry_after {
            Some(seconds) => Duration::from_secs(seconds.max(1)),
            None => Duration::from_millis(250 * 2u64.pow(attempt)),
        };
        tokio::time::sleep(wait).await;
    }
}

async fn api_error(status: StatusCode, response: Response) -> ApiError {
    let body = response.bytes().await.unwrap_or_default();
    let parsed: Option<Wrapper> = serde_json::from_slice(&body).ok();
    match parsed {
        Some(Wrapper { mut error }) => {
            error.status = status.as_u16();
            error
        }
        None => ApiError {
            status: status.as_u16(),
            code: "INTERNAL".into(),
            message: format!("the server returned {status} with no error body"),
            retryable: status.is_server_error(),
            request_id: "-".into(),
            suggested_action: "Retry, and quote the status if it persists.".into(),
            doc: String::new(),
            path: None,
            meta: Default::default(),
        },
    }
}

#[derive(serde::Deserialize)]
struct Wrapper {
    error: ApiError,
}

fn header_seconds(response: &Response, name: header::HeaderName) -> Option<u64> {
    response.headers().get(name)?.to_str().ok()?.parse().ok()
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = if self.api_key.len() > 12 { &self.api_key[..9] } else { "" };
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("api_key", &format_args!("{key}..."))
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

#[doc(hidden)]
pub const OXIDISED: &str = "Iron, oxidised on purpose. No unsafe, no panics, no \
                            leaked keys. — Direct Softworks";
