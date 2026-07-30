//! Transfer checks before any model call leaves the process.

use std::net::ToSocketAddrs;

use brolga_config::policy::{Capability, PolicyIdentity, decide};
use brolga_model::MarkingSet;
use brolga_security::NetworkPolicy;

use crate::error::LlmError;

/// Whether the endpoint stays on the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferClass {
    /// Loopback / Unix-socket style local runtime.
    Local,
    /// Off-host network destination.
    Remote,
}

/// What a transfer would send and where.
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Caller identity.
    pub identity: PolicyIdentity,
    /// Markings on the material that would be included in the prompt.
    pub markings: MarkingSet,
    /// Endpoint URL or host:port string used for SSRF checks when remote.
    pub endpoint: String,
    /// Local vs remote classification (caller computes; verified for loopback when remote claimed).
    pub class: TransferClass,
}

/// Classify an endpoint host as local or remote.
///
/// # Errors
///
/// Unparseable endpoint.
pub fn classify_endpoint(endpoint: &str) -> Result<TransferClass, LlmError> {
    let host = host_from_endpoint(endpoint)?;
    if is_loopback_host(&host) {
        Ok(TransferClass::Local)
    } else {
        Ok(TransferClass::Remote)
    }
}

/// Run policy + network checks.
///
/// # Errors
///
/// Policy or network refusal.
pub fn check_transfer(request: &TransferRequest, network: &NetworkPolicy) -> Result<(), LlmError> {
    let required = match request.class {
        // Local models still read intelligence content into a prompt.
        TransferClass::Local => Capability::Read,
        // Remote providers receive a copy of the material.
        TransferClass::Remote => Capability::Redistribute,
    };

    if !request.identity.can(required) {
        return Err(LlmError::Policy {
            reason: format!(
                "identity `{}` lacks capability `{}`",
                request.identity.name,
                required.as_str()
            ),
        });
    }

    let decision = decide(&request.identity, &request.markings, required);
    if !decision.allowed {
        let reason = decision
            .denials
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(LlmError::Policy {
            reason: if reason.is_empty() {
                "markings refuse transfer".to_owned()
            } else {
                reason
            },
        });
    }

    if request.class == TransferClass::Remote {
        check_network_endpoint(&request.endpoint, network)?;
    }

    Ok(())
}

fn check_network_endpoint(endpoint: &str, network: &NetworkPolicy) -> Result<(), LlmError> {
    let host = host_from_endpoint(endpoint)?;
    let port = port_from_endpoint(endpoint).unwrap_or(443);
    let candidate = format!("{host}:{port}");
    let addrs = candidate
        .to_socket_addrs()
        .map_err(|error| LlmError::Network {
            reason: format!("resolve `{host}`: {error}"),
        })?;
    let mut any = false;
    for addr in addrs {
        any = true;
        network
            .permits_address(addr.ip())
            .map_err(|error| LlmError::Network {
                reason: error.to_string(),
            })?;
    }
    if !any {
        return Err(LlmError::Network {
            reason: format!("host `{host}` resolved to no addresses"),
        });
    }
    Ok(())
}

fn host_from_endpoint(endpoint: &str) -> Result<String, LlmError> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err(LlmError::Config {
            reason: "endpoint must not be empty".to_owned(),
        });
    }
    // Accept bare host, host:port, or http(s)://host[:port]/path
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = if host_port.starts_with('[') {
        // [::1]:11434
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host_port)
            .to_owned()
    } else {
        host_port.split(':').next().unwrap_or(host_port).to_owned()
    };
    if host.is_empty() {
        return Err(LlmError::Config {
            reason: format!("cannot parse host from `{endpoint}`"),
        });
    }
    Ok(host)
}

fn port_from_endpoint(endpoint: &str) -> Option<u16> {
    let without_scheme = endpoint
        .trim()
        .strip_prefix("https://")
        .or_else(|| endpoint.trim().strip_prefix("http://"))
        .unwrap_or(endpoint.trim());
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_port.starts_with('[') {
        host_port.split("]:").nth(1).and_then(|p| p.parse().ok())
    } else {
        host_port.split_once(':').and_then(|(_, p)| p.parse().ok())
    }
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "0:0:0:0:0:0:0:1"
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use brolga_config::policy::Capability;
    use brolga_model::{Marking, MarkingSet, TlpLevel};
    use brolga_security::NetworkPolicy;

    fn identity_with(cap: Capability) -> PolicyIdentity {
        PolicyIdentity::anonymous().with_capability(cap)
    }

    #[test]
    fn remote_requires_redistribute() {
        let request = TransferRequest {
            identity: PolicyIdentity::anonymous(),
            markings: MarkingSet::empty(),
            endpoint: "https://api.openai.com".to_owned(),
            class: TransferClass::Remote,
        };
        let err = check_transfer(&request, &NetworkPolicy::strict()).unwrap_err();
        assert!(matches!(err, LlmError::Policy { .. }));
    }

    #[test]
    fn local_allows_read_only() {
        let request = TransferRequest {
            identity: PolicyIdentity::anonymous(),
            markings: MarkingSet::empty(),
            endpoint: "http://127.0.0.1:11434".to_owned(),
            class: TransferClass::Local,
        };
        assert!(check_transfer(&request, &NetworkPolicy::strict()).is_ok());
    }

    #[test]
    fn restricted_markings_block_even_with_capability() {
        let identity = identity_with(Capability::Redistribute);
        let markings = MarkingSet::from_iter([Marking::Tlp(TlpLevel::Red)]);
        // anonymous max is CLEAR — still refuse red
        let request = TransferRequest {
            identity: PolicyIdentity::anonymous().with_capability(Capability::Redistribute),
            markings,
            endpoint: "https://api.example.com".to_owned(),
            class: TransferClass::Remote,
        };
        let _ = identity;
        assert!(check_transfer(&request, &NetworkPolicy::strict()).is_err());
    }

    #[test]
    fn classify_localhost() {
        assert_eq!(
            classify_endpoint("http://localhost:11434").unwrap(),
            TransferClass::Local
        );
        assert_eq!(
            classify_endpoint("https://api.openai.com/v1").unwrap(),
            TransferClass::Remote
        );
    }
}
