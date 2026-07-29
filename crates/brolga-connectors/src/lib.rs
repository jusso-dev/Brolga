//! Read-only outbound retrieval: transport policy, sync state, and protocol clients.
//!
//! Added by [ADR 0005](https://github.com/jusso-dev/Brolga/blob/main/docs/adr/0005-connector-crate-boundary-and-outbound-network-policy.md),
//! which amends ADR 0001 §1 and records the project exception this crate represents: **Brolga makes
//! outbound requests in a default build.** Every byte it read before now was handed to it. That is
//! a different threat model, and the shape of this crate is the response to it.
//!
//! # The three properties worth stating plainly
//!
//! **One outbound path.** Every protocol client is written against [`Transport`], and the only
//! implementation that opens a socket is [`PolicyTransport`], which applies
//! [`NetworkPolicy`](brolga_security::NetworkPolicy) per request and per redirect hop. A client
//! holding a `&dyn Transport` cannot reach the network another way, so auditing outbound safety
//! means reading one file rather than every connector anybody adds later.
//!
//! **Redirects are ours, not the agent's.** The HTTP agent has redirect-following disabled. An
//! agent that follows them internally connects before any check runs, which makes the SSRF controls
//! decorative — a `302` to `http://169.254.169.254/` would be fetched and the policy that would
//! have refused it never consulted.
//!
//! **The cursor never moves ahead of stored data.** A page is fetched, ingested, and only then does
//! the cursor advance. The reverse ordering produces a silent, permanent gap: the window is never
//! re-fetched and nothing reports an error, because the next run simply starts after it.
//!
//! # Read-only is structural
//!
//! [`Transport`] has no method that sends a body. A publishing connector is a new ADR, not a method
//! added here — "keep upstream connectors read-only by default" is worth more as a shape than as a
//! default somebody can flip.
//!
//! # Example
//!
//! ```no_run
//! use brolga_connectors::{PolicyTransport, TaxiiClient};
//! use brolga_security::NetworkPolicy;
//!
//! let transport = PolicyTransport::new(NetworkPolicy::strict());
//! let mut client = TaxiiClient::new(&transport);
//!
//! let discovery = client.discover("https://taxii.example.org")?;
//! for api_root in &discovery.api_roots {
//!     for collection in client.collections(api_root)? {
//!         println!("{} — {}", collection.id, collection.title);
//!     }
//! }
//! # Ok::<(), brolga_connectors::ConnectorError>(())
//! ```

#![forbid(unsafe_code)]

pub mod error;
pub mod misp;
pub mod opencti;
pub mod sync;
pub mod taxii;
pub mod transport;

pub use error::ConnectorError;
pub use misp::{MISP_CONNECTOR, MispClient, MispFeed, MispInstance, MispPage};
pub use opencti::{OPENCTI_CONNECTOR, OpenCtiClient, OpenCtiInstance, OpenCtiPage};
pub use sync::{
    FeedRef, MispTarget, SyncOptions, SyncReport, TAXII_CONNECTOR, sync_collection, sync_misp_feed,
    sync_opencti,
};
pub use taxii::{Collection, Discovery, ObjectPage, TaxiiClient, TaxiiVersion};
pub use transport::{
    MAX_RESPONSE_BYTES, PolicyTransport, QueryOperation, QueryRequest, Request, Response, Transport,
};
