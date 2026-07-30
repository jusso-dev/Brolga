//! Pure-compute echo plugin for host integration tests.
//!
//! - `manifest.get` returns a fixed valid manifest JSON.
//! - `invoke.call` for `parser` / `1.0` echoes a tiny parse response; other extensions error.
//!
//! No host imports. No filesystem, network, clock, or entropy.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

#[allow(warnings)]
mod bindings;

use bindings::brolga::plugin::types::PluginError;
use bindings::exports::brolga::plugin::invoke::Guest as InvokeGuest;
use bindings::exports::brolga::plugin::manifest::Guest as ManifestGuest;

struct Component;

const MANIFEST_JSON: &str = r#"{
  "schema_version": "brolga.plugin.manifest/1.0",
  "name": "example.parser.echo",
  "version": "1.0.0",
  "api": "0.1.0",
  "extension_points": [
    {
      "kind": "parser",
      "contract_version": "1.0",
      "formats": ["application/x-echo"],
      "outputs": ["claim"]
    }
  ],
  "capabilities": []
}"#;

impl ManifestGuest for Component {
    fn get() -> Result<String, PluginError> {
        Ok(MANIFEST_JSON.to_owned())
    }
}

impl InvokeGuest for Component {
    fn call(
        extension: String,
        contract_version: String,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, PluginError> {
        if extension != "parser" {
            return Err(PluginError {
                code: "unknown-extension".to_owned(),
                message: format!("echo guest only implements parser, got `{extension}`"),
            });
        }
        if contract_version != "1.0" && contract_version != "1.0.0" {
            return Err(PluginError {
                code: "unsupported-contract".to_owned(),
                message: format!("echo guest speaks 1.0, got `{contract_version}`"),
            });
        }
        if request.len() > 8 * 1024 * 1024 {
            return Err(PluginError {
                code: "limit-exceeded".to_owned(),
                message: "request too large".to_owned(),
            });
        }
        let body = format!(
            r#"{{"records":[],"echo_bytes":{},"note":"pure-compute"}}"#,
            request.len()
        );
        Ok(body.into_bytes())
    }
}

bindings::export!(Component with_types_in bindings);
