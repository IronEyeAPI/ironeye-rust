//! Request and response shapes, transcribed from the server's own types.
//!
//! Response structs carry the fields the contract guarantees and nothing more.
//! A module's own body is left as `serde_json::Value`, because every module
//! returns a different shape and a fixed struct would fail to deserialise the
//! moment the engine learned to report one more thing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The document. Exactly one of `text`, `base64` or `url`: two is refused, and
/// so is none.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

impl Source {
    pub fn text(value: impl Into<String>) -> Self {
        Self { text: Some(value.into()), ..Default::default() }
    }

    pub fn bytes(value: &[u8]) -> Self {
        Self { base64: Some(base64(value)), ..Default::default() }
    }

    pub fn url(value: impl Into<String>) -> Self {
        Self { url: Some(value.into()), ..Default::default() }
    }

    pub fn named(mut self, filename: impl Into<String>) -> Self {
        self.filename = Some(filename.into());
        self
    }

    pub fn declared(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Output {
    pub mode: String,
    pub include_findings: bool,
}

/// The one body every analysis route and the job route share.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AnalyzeRequest {
    pub input: Source,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Output>,
    /// Zero keeps nothing. Above the deployment's ceiling it is refused rather
    /// than clamped, so a caller cannot believe they asked for less than they did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_seconds: Option<u64>,
}

impl AnalyzeRequest {
    pub fn new(input: Source) -> Self {
        Self { input, ..Default::default() }
    }

    pub fn preset(mut self, preset: impl Into<String>) -> Self {
        self.preset = Some(preset.into());
        self
    }

    pub fn features<I, S>(mut self, features: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.features = features.into_iter().map(Into::into).collect();
        self
    }

    pub fn option(mut self, module: impl Into<String>, value: Value) -> Self {
        self.options.insert(module.into(), value);
        self
    }

    pub fn redacted(mut self) -> Self {
        self.output = Some(Output { mode: "redacted".into(), include_findings: true });
        self
    }

    pub fn retention(mut self, seconds: u64) -> Self {
        self.retention_seconds = Some(seconds);
        self
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Evidence {
    pub text_span: Option<[usize; 2]>,
    pub page: Option<u32>,
    pub bbox: Option<[f32; 4]>,
    pub time_range: Option<[f32; 2]>,
    pub container_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Method {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
    pub model: Option<String>,
    pub provider: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub category: String,
    pub epistemic: String,
    pub value: Option<String>,
    pub normalized: Option<Value>,
    pub confidence: f64,
    pub severity: Option<String>,
    pub status: String,
    pub sensitive: bool,
    #[serde(default)]
    pub redacted: bool,
    pub evidence: Evidence,
    #[serde(default)]
    pub attributes: BTreeMap<String, Value>,
    pub method: Method,
    pub created_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModuleResult {
    pub status: String,
    #[serde(default)]
    pub cached: bool,
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Whatever else the module reported.
    #[serde(flatten)]
    pub data: BTreeMap<String, Value>,
}

pub type Section = BTreeMap<String, ModuleResult>;

#[derive(Debug, Clone, Deserialize)]
pub struct InputSummary {
    pub sha256: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub channel: String,
    pub filename: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Provenance {
    pub modules: BTreeMap<String, Value>,
    pub degraded: Vec<String>,
    pub elapsed_ms: f64,
    pub audit: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Retention {
    pub seconds: u64,
    pub mode: String,
    pub expires_at: Option<String>,
    pub stored: String,
}

/// The answer to every analysis call. The sections are named for how the engine
/// came to know each one, and nothing crosses between them.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    pub request_id: String,
    pub status: String,
    pub engine: BTreeMap<String, String>,
    pub input: InputSummary,
    #[serde(default)]
    pub classification: Value,
    #[serde(default)]
    pub observed: Section,
    #[serde(default)]
    pub derived: Section,
    #[serde(default)]
    pub inferred: Section,
    #[serde(default)]
    pub validated: Section,
    #[serde(default)]
    pub safety: Section,
    #[serde(default)]
    pub privacy: Section,
    #[serde(default)]
    pub security: Section,
    #[serde(default)]
    pub compliance: Section,
    pub provenance: Provenance,
    pub retention: Retention,
    #[serde(default)]
    pub actions: Vec<Value>,
    pub created_at: String,
}

impl Envelope {
    /// Every finding in the envelope, whichever section reported it.
    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        [
            &self.observed,
            &self.derived,
            &self.inferred,
            &self.validated,
            &self.safety,
            &self.privacy,
            &self.security,
            &self.compliance,
        ]
        .into_iter()
        .flat_map(|section| section.values())
        .flat_map(|result| result.findings.iter())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: String,
    pub status: String,
    #[serde(default)]
    pub retention_seconds: Option<u64>,
    pub created_at: String,
    #[serde(default)]
    pub result: Option<Envelope>,
}

impl Job {
    pub fn done(&self) -> bool {
        matches!(self.status.as_str(), "completed" | "failed")
    }
}

/// What a collection call declares about itself. Required on any operation
/// whose `personal_data` flag is true: the server refuses rather than assumes.
#[derive(Debug, Clone, Default)]
pub struct Declaration {
    pub legal_basis: Option<String>,
    pub purpose: Option<String>,
    pub controller: Option<String>,
    pub basis_evidence: Option<String>,
    pub special_condition: Option<String>,
    pub projection: Option<String>,
}

impl Declaration {
    pub fn new(legal_basis: impl Into<String>, purpose: impl Into<String>) -> Self {
        Self {
            legal_basis: Some(legal_basis.into()),
            purpose: Some(purpose.into()),
            ..Default::default()
        }
    }

    pub fn evidence(mut self, reference: impl Into<String>) -> Self {
        self.basis_evidence = Some(reference.into());
        self
    }

    pub fn projection(mut self, level: impl Into<String>) -> Self {
        self.projection = Some(level.into());
        self
    }

    pub(crate) fn headers(&self) -> Vec<(&'static str, String)> {
        [
            ("X-Legal-Basis", &self.legal_basis),
            ("X-Purpose", &self.purpose),
            ("X-Controller", &self.controller),
            ("X-Basis-Evidence", &self.basis_evidence),
            ("X-Special-Condition", &self.special_condition),
            ("X-Projection", &self.projection),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.clone().map(|value| (name, value)))
        .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CollectionMeta {
    pub source: String,
    pub source_kind: String,
    pub duration_ms: f64,
    pub records: usize,
    pub attempts: u32,
    #[serde(default)]
    pub cached: bool,
}

/// The answer to a collection operation. `data` is one record, or an array of
/// them where the operation is a list.
#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    pub request_id: String,
    pub operation: String,
    pub entity: String,
    pub data: Value,
    pub collection: CollectionMeta,
    #[serde(default)]
    pub compliance: Value,
    #[serde(default)]
    pub paging: Option<Paging>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Paging {
    pub next_cursor: Option<String>,
    pub total: Option<u64>,
}

/// Names a person on a platform, for the rights endpoints. The identifier never
/// reaches a log: the service records a salted digest instead.
#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub platform: String,
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Subject {
    pub fn new(platform: impl Into<String>, identifier: impl Into<String>) -> Self {
        Self { platform: platform.into(), identifier: identifier.into(), reference: None }
    }
}

/// Standard base64, without pulling a dependency in for sixteen lines.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
        }
        // A short final chunk encoded three zero bytes; the characters those
        // zeroes produced are replaced by padding rather than left to decode
        // back into bytes that were never there.
        let padding = 3 - chunk.len();
        out.truncate(out.len() - padding);
        out.extend(std::iter::repeat_n('=', padding));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_reference_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
