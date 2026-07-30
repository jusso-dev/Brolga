//! Pure-compute fixture plugin for host integration tests (#48 / #50).
//!
//! - `manifest.get` returns a fixed valid manifest JSON (parser + exporter points).
//! - `invoke.call` for `parser` / `1.0` echoes a tiny parse response.
//! - `invoke.call` for `exporter` / `1.0` returns a tiny CSV with declared lossiness.
//! - Unknown extension names and unsupported contract versions fail clearly.
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
  "name": "example.fixture.echo",
  "version": "1.0.0",
  "api": "0.1.0",
  "extension_points": [
    {
      "kind": "parser",
      "contract_version": "1.0",
      "formats": ["application/x-echo"],
      "outputs": ["claim"]
    },
    {
      "kind": "exporter",
      "contract_version": "1.0",
      "formats": ["text/csv", "acme-csv"],
      "outputs": ["acme-csv"]
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
        match extension.as_str() {
            "parser" => {
                // Host retains original bytes and transformations outside the guest.
                // Plugin only returns records the host will re-validate against brolga-model.
                let body = format!(
                    r#"{{"records":[],"echo_bytes":{},"note":"pure-compute; host preserves originals"}}"#,
                    request.len()
                );
                Ok(body.into_bytes())
            }
            "exporter" => {
                // Host already ran the policy gate (ADR 0007) before building this request.
                // Guest only formats bytes and must declare lossiness.
                // body is ByteBuf = sequence of u8: "id,value\n" = [105,100,44,118,97,108,117,101,10]
                let body = r#"{"body":[105,100,44,118,97,108,117,101,10],"media_type":"text/csv","lossiness":"derived","declared_losses":["CSV drops provenance, markings, and graph structure; host policy already cleared the pack"]}"#;
                Ok(body.as_bytes().to_vec())
            }
            other => Err(PluginError {
                code: "unknown-extension".to_owned(),
                message: format!("echo guest implements parser and exporter, got `{other}`"),
            }),
        }
    }
}

bindings::export!(Component with_types_in bindings);
