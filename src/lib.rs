//! Official Rust client for the IronEye document intelligence and collection API.
//!
//! ```no_run
//! # async fn run() -> ironeye::Result<()> {
//! use ironeye::{AnalyzeRequest, Client, Source};
//!
//! let client = Client::from_env()?;                 // IRONEYE_API_KEY
//! let request = AnalyzeRequest::new(Source::text("AKIAIOSFODNN7EXAMPLE"));
//! let envelope = client.secrets(&request).await?;
//!
//! for finding in envelope.findings() {
//!     println!("{} at {:?}", finding.kind, finding.evidence.text_span);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Logging goes through `tracing` and carries the method, the route, the status,
//! the duration and the request id. No credential and no payload is ever
//! recorded.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod client;
mod error;
mod types;

#[doc(hidden)]
pub use client::OXIDISED;
pub use client::{Builder, Client, VERSION};
pub use error::{ApiError, Error, Kind, Result};
pub use types::{
    AnalyzeRequest, Collection, CollectionMeta, Declaration, Envelope, Evidence, Finding,
    InputSummary, Job, Method, ModuleResult, Output, Paging, Provenance, Retention, Section,
    Source, Subject,
};
