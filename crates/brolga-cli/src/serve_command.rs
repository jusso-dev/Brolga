//! `brolga serve` — run the read-only HTTP API.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use brolga_api::{ApiConfig, ApiState, Credential};

use crate::cli::ServeArgs;
use crate::exit::ExitCode;
use crate::output::Streams;

/// The environment variable the bearer token is read from.
///
/// An environment variable rather than a flag, because a flag lands in the process table where
/// every other user on the host can read it, and in the shell history of whoever typed it.
pub(crate) const TOKEN_VARIABLE: &str = "BROLGA_API_TOKEN";

/// Redact userinfo in postgres URLs so serve startup notes never print passwords.
fn redact_database_label(spec: &str) -> String {
    if let Some(at) = spec.find('@')
        && let Some(scheme) = spec.find("://")
    {
        let head = spec.get(..=scheme + 2).unwrap_or("postgres://");
        let tail = spec.get(at..).unwrap_or("@");
        return format!("{head}***{tail}");
    }
    spec.to_owned()
}

/// Serve the API until the process is asked to stop.
pub(crate) fn serve<Out: Write, Err: Write>(
    args: &ServeArgs,
    streams: &mut Streams<Out, Err>,
) -> ExitCode {
    let address: SocketAddr = match args.bind.parse() {
        Ok(address) => address,
        Err(error) => {
            let _ = streams.problem(&format!(
                "cannot parse --bind {:?}: {error}. Expected host:port, such as 127.0.0.1:8787.",
                args.bind
            ));
            return ExitCode::Usage;
        }
    };

    // Read before binding, so a rejected token fails at startup rather than on the first request.
    let credential = match std::env::var(TOKEN_VARIABLE) {
        Ok(token) => match Credential::new(token) {
            Ok(credential) => Some(credential),
            Err(error) => {
                let _ = streams.problem(&format!("{TOKEN_VARIABLE} is not usable: {error}"));
                return ExitCode::ConfigInvalid;
            }
        },
        Err(_) => None,
    };

    let config = match ApiConfig::bind(address, credential) {
        Ok(config) => config,
        Err(error) => {
            // The refusal that matters: a reachable address with no token. The message names the
            // variable to set, because "configure authentication" without saying how is what makes
            // someone reach for 127.0.0.1 and give up on the deployment they wanted.
            let _ = streams.problem(&format!(
                "{error} Set {TOKEN_VARIABLE} to a token of at least {} characters.",
                Credential::MIN_LENGTH
            ));
            return ExitCode::ConfigInvalid;
        }
    };

    let config = match config.with_request_timeout(Duration::from_secs(args.timeout_seconds)) {
        Ok(config) => config,
        Err(error) => {
            let _ = streams.problem(&format!("--timeout-seconds is not usable: {error}"));
            return ExitCode::Usage;
        }
    };

    let store = match crate::store_commands::open_store(&args.database, streams) {
        Ok(store) => store,
        Err(code) => return code,
    };

    let authenticated = config.requires_authentication();
    let state = Arc::new(ApiState::new(store, config));

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = streams.problem(&format!("cannot start the async runtime: {error}"));
            return ExitCode::Io;
        }
    };

    let database_label = redact_database_label(&args.database.display().to_string());
    let _ = streams.note(&format!(
        "serving {database_label} on http://{address}/api/v1 ({})",
        if authenticated {
            "bearer token required"
        } else {
            "loopback, no token required"
        }
    ));

    match runtime.block_on(brolga_api::serve(state)) {
        Ok(()) => ExitCode::Success,
        Err(error) => {
            let _ = streams.problem(&format!("cannot serve on {address}: {error}"));
            ExitCode::Io
        }
    }
}
