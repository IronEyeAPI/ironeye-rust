//! The error contract.
//!
//! `retryable` is the server's own verdict rather than an inference from the
//! status code: a 429 from a spent monthly allowance is not the same wait as a
//! 429 from a rate limiter, and only the body tells them apart.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The body the server sends on every refusal.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: u16,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub suggested_action: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub meta: BTreeMap<String, serde_json::Value>,
}

impl ApiError {
    /// The family the code belongs to, for a caller matching on meaning rather
    /// than on a status number four unrelated refusals share.
    pub fn kind(&self) -> Kind {
        match self.code.as_str() {
            "UNAUTHENTICATED" => Kind::Unauthenticated,
            "FORBIDDEN_SCOPE" | "PLAN_LIMITED" => Kind::Forbidden,
            "RATE_LIMITED" | "QUOTA_EXHAUSTED" | "TENANT_BUSY" => Kind::RateLimited,
            "NOT_FOUND" => Kind::NotFound,
            "COMPLIANCE_REFUSED" | "COLLECTION_BLOCKED" => Kind::Compliance,
            "SOURCE_NOT_CONFIGURED" | "UPSTREAM_REFUSED" | "UPSTREAM_THROTTLED" => Kind::Upstream,
            "INTERNAL" | "DEPENDENCY_UNAVAILABLE" | "SERVER_DRAINING" => Kind::Server,
            _ => Kind::InvalidRequest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Unauthenticated,
    Forbidden,
    RateLimited,
    InvalidRequest,
    NotFound,
    Compliance,
    Upstream,
    Server,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The server refused, and said why.
    ///
    /// Boxed because `ApiError` is far wider than any other variant, and an
    /// un-boxed one would make every `Result` in the crate that size.
    #[error("{}: {} (request_id={})", .0.code, .0.message, .0.request_id)]
    Api(#[from] Box<ApiError>),

    /// The request never got an answer.
    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    /// The answer arrived but was not the shape this version expects.
    #[error("decoding the response: {0}")]
    Decode(#[from] serde_json::Error),

    #[error("configuration: {0}")]
    Config(String),

    #[error("timed out waiting for job {job_id} (last status: {status})")]
    JobTimeout { job_id: String, status: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {} (request_id={})", self.code, self.message, self.request_id)
    }
}

impl std::error::Error for ApiError {}

pub type Result<T> = std::result::Result<T, Error>;
