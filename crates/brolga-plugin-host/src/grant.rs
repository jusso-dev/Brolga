//! Operator capability grants: intersection with plugin requests.

use brolga_plugin_sdk::Capability;

use crate::error::HostError;

/// An operator-approved capability grant.
///
/// Same shape as a plugin request, but owned by the host configuration rather than the guest.
pub type CapabilityGrant = Capability;

/// The set of capabilities the operator allows for one plugin installation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantSet {
    grants: Vec<CapabilityGrant>,
}

impl GrantSet {
    /// No grants — pure compute only.
    #[must_use]
    pub const fn empty() -> Self {
        Self { grants: Vec::new() }
    }

    /// Build from an explicit list. Each grant is validated.
    ///
    /// # Errors
    ///
    /// Invalid scopes (wildcards, empty hosts, …).
    pub fn try_from_grants(grants: Vec<CapabilityGrant>) -> Result<Self, HostError> {
        for grant in &grants {
            grant
                .validate()
                .map_err(|error| HostError::CapabilityDenied {
                    reason: error.to_string(),
                })?;
        }
        Ok(Self { grants })
    }

    /// Borrow the grants.
    #[must_use]
    pub fn as_slice(&self) -> &[CapabilityGrant] {
        &self.grants
    }

    /// Whether every requested capability is covered by a grant.
    ///
    /// Coverage is exact for flag-like caps and prefix/host equality for scoped ones — never a
    /// wildcard expansion.
    ///
    /// # Errors
    ///
    /// [`HostError::CapabilityDenied`] naming the first uncovered request.
    pub fn authorise(&self, requested: &[Capability]) -> Result<(), HostError> {
        for request in requested {
            if !self.covers(request) {
                return Err(HostError::CapabilityDenied {
                    reason: format!(
                        "plugin requests `{}` which the operator did not grant",
                        request.kind_str()
                    ),
                });
            }
        }
        Ok(())
    }

    fn covers(&self, request: &Capability) -> bool {
        self.grants.iter().any(|grant| grant_covers(grant, request))
    }
}

fn grant_covers(grant: &Capability, request: &Capability) -> bool {
    match (grant, request) {
        (Capability::WallClock, Capability::WallClock)
        | (Capability::Entropy, Capability::Entropy) => true,
        (
            Capability::ReadFilesystem {
                path_prefix: granted,
            },
            Capability::ReadFilesystem { path_prefix: asked },
        )
        | (
            Capability::WriteFilesystem {
                path_prefix: granted,
            },
            Capability::WriteFilesystem { path_prefix: asked },
        ) => path_covers(granted, asked),
        (
            Capability::NetworkEgress {
                host: granted_host,
                port: granted_port,
            },
            Capability::NetworkEgress {
                host: asked_host,
                port: asked_port,
            },
        ) => hosts_equal(granted_host, asked_host) && ports_cover(*granted_port, *asked_port),
        _ => false,
    }
}

fn path_covers(granted: &str, asked: &str) -> bool {
    let granted = granted.trim_end_matches(['/', '\\']);
    let asked = asked.trim_end_matches(['/', '\\']);
    asked == granted
        || asked.starts_with(&(granted.to_owned() + "/"))
        || asked.starts_with(&(granted.to_owned() + "\\"))
}

fn hosts_equal(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn ports_cover(granted: Option<u16>, asked: Option<u16>) -> bool {
    match (granted, asked) {
        // Grant without a port covers any asked port for that host (still one host).
        (None, _) => true,
        (Some(g), Some(a)) => g == a,
        // Grant is port-specific; request is any-port — refuse.
        (Some(_), None) => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_grant_allows_no_capabilities() {
        let grants = GrantSet::empty();
        assert!(grants.authorise(&[]).is_ok());
        assert!(grants.authorise(&[Capability::WallClock]).is_err());
    }

    #[test]
    fn path_prefix_covers_children() {
        let grants = GrantSet::try_from_grants(vec![Capability::ReadFilesystem {
            path_prefix: "/var/brolga/feeds".to_owned(),
        }])
        .unwrap();
        assert!(
            grants
                .authorise(&[Capability::ReadFilesystem {
                    path_prefix: "/var/brolga/feeds/acme".to_owned(),
                }])
                .is_ok()
        );
        assert!(
            grants
                .authorise(&[Capability::ReadFilesystem {
                    path_prefix: "/etc".to_owned(),
                }])
                .is_err()
        );
    }
}
