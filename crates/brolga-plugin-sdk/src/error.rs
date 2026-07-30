//! Structured plugin and SDK errors.
//!
//! Every variant names what failed and what would have been acceptable. A validation error an
//! operator cannot act on is a failure of the validator, not of the plugin.

use thiserror::Error;

/// What went wrong loading, validating, or negotiating a plugin surface.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PluginError {
    /// The document was not readable as YAML or JSON.
    #[error("the plugin manifest is not readable: {0}")]
    Unreadable(String),

    /// The document declared no schema tag, or one this build does not accept.
    #[error(
        "the plugin manifest declares `schema_version: {found}`; this build accepts {accepted}. A \
         manifest whose vintage is unknown is refused rather than read on a guess"
    )]
    UnknownSchema {
        /// What the document said.
        found: String,
        /// What this build would have accepted.
        accepted: String,
    },

    /// A required top-level field was missing or empty.
    #[error("the plugin manifest has no usable `{field}`, which every manifest must state")]
    Missing {
        /// The field name.
        field: &'static str,
    },

    /// A field was present but unusable.
    #[error("plugin manifest field `{field}`: {reason}")]
    Field {
        /// Which field.
        field: &'static str,
        /// What was wrong.
        reason: String,
    },

    /// An API or contract version string could not be parsed.
    #[error("version `{found}` is not a valid `major.minor` or `major.minor.patch`: {reason}")]
    MalformedVersion {
        /// The string as written.
        found: String,
        /// Why it was refused.
        reason: String,
    },

    /// The plugin's declared API range does not include this build's ABI.
    #[error(
        "plugin API range `{range}` does not include this build's ABI {abi}. Unknown or future \
         majors fail clearly rather than running on a guess"
    )]
    IncompatibleApi {
        /// The range the manifest declared.
        range: String,
        /// This build's ABI version.
        abi: String,
    },

    /// An extension point name this build does not know.
    #[error(
        "unknown extension point `{found}`. This build knows: {known}. An unknown point is refused \
         rather than ignored, so a typo cannot silently disable a plugin"
    )]
    UnknownExtension {
        /// What the document said.
        found: String,
        /// Comma-separated known names.
        known: String,
    },

    /// A contract version the extension point does not support.
    #[error(
        "extension `{extension}` declares contract `{found}`; this build implements \
         `{supported}` (major must match; newer minors are accepted)"
    )]
    UnsupportedContract {
        /// Which extension point.
        extension: String,
        /// What the manifest asked for.
        found: String,
        /// What this build implements.
        supported: String,
    },

    /// A capability name this build does not know, or a scoped capability missing its scope.
    #[error("capability: {reason}")]
    Capability {
        /// What was wrong.
        reason: String,
    },

    /// A capability attempted to use a wildcard or implicit host-wide grant.
    #[error(
        "capability refused: {reason}. Plugin capabilities are least privilege; there is no \
         wildcard host access"
    )]
    WildcardCapability {
        /// What was wrong.
        reason: String,
    },

    /// The ABI or WIT document embedded in this build failed an integrity check.
    #[error("plugin ABI: {reason}")]
    Abi {
        /// What was wrong.
        reason: String,
    },
}
