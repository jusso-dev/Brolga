//! End-to-end tests against the compiled `brolga` binary.
//!
//! The unit tests exercise the command functions. These run the actual process, because the
//! properties #7 asks about — the binary's name, the stdout/stderr split, exit codes as a process
//! sees them, and what does or does not reach a log — are properties of the *process* and are not
//! observable from inside it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;
use std::process::{Command, Output};

/// Run the compiled binary.
fn brolga(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brolga"))
        .args(arguments)
        .output()
        .expect("the brolga binary must run")
}

/// Run the binary with extra environment variables.
fn brolga_with_env(arguments: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_brolga"));
    command.args(arguments);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().expect("the brolga binary must run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout must be UTF-8")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8")
}

fn code(output: &Output) -> i32 {
    output
        .status
        .code()
        .expect("the process must exit normally")
}

// -------------------------------------------------------------------------------------------------
// Identity
// -------------------------------------------------------------------------------------------------

#[test]
fn the_binary_is_named_brolga() {
    let path = Path::new(env!("CARGO_BIN_EXE_brolga"));
    let name = path.file_stem().unwrap().to_string_lossy();
    assert_eq!(name, "brolga");

    let version = brolga(&["--version"]);
    assert_eq!(code(&version), 0);
    assert!(
        stdout(&version).starts_with("brolga "),
        "{}",
        stdout(&version)
    );
}

#[test]
fn help_lists_the_commands_including_the_unimplemented_ones() {
    // Hiding them would make a script written for a later Brolga fail with "unrecognised
    // subcommand" instead of a message about the version.
    let output = brolga(&["--help"]);
    assert_eq!(code(&output), 0);

    let help = stdout(&output);
    for command in [
        "init",
        "doctor",
        "config",
        "exit-codes",
        "ingest",
        "context",
    ] {
        assert!(help.contains(command), "help omits {command}: {help}");
    }
}

// -------------------------------------------------------------------------------------------------
// Streams
// -------------------------------------------------------------------------------------------------

#[test]
fn results_go_to_stdout_and_diagnostics_go_to_stderr() {
    // The rule that makes `brolga ... | jq` work.
    let output = brolga(&["--output", "json", "config", "validate"]);
    assert_eq!(code(&output), 0);

    // stdout parses as exactly one JSON document, with nothing else mixed in.
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("stdout must be one JSON document");
    assert_eq!(parsed["status"], "valid");
}

#[test]
fn a_failure_writes_nothing_to_stdout() {
    // A script reading stdout must not see a partial result on the failure path.
    let output = brolga(&["--config", "/does/not/exist.yaml", "config", "validate"]);
    assert_ne!(code(&output), 0);
    assert!(stdout(&output).is_empty(), "stdout: {}", stdout(&output));
    assert!(!stderr(&output).is_empty(), "the failure must be explained");
}

#[test]
fn structured_output_stays_parseable_with_diagnostics_enabled() {
    // Logs on stdout would break this, intermittently, whenever the condition that produces a
    // message happens to occur.
    let output = brolga_with_env(
        &["--output", "json", "--log-level", "trace", "exit-codes"],
        &[("BROLGA_LOG", "trace")],
    );
    assert_eq!(code(&output), 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output))
        .expect("stdout must remain one JSON document at trace level");
    assert!(parsed.as_array().is_some_and(|codes| !codes.is_empty()));
}

#[test]
fn quiet_silences_commentary_but_not_the_result() {
    let loud = brolga(&["config", "validate"]);
    let quiet = brolga(&["--quiet", "config", "validate"]);

    assert_eq!(code(&loud), 0);
    assert_eq!(code(&quiet), 0);
    assert_eq!(
        stdout(&loud),
        stdout(&quiet),
        "--quiet must not change the result",
    );
}

// -------------------------------------------------------------------------------------------------
// Exit codes
// -------------------------------------------------------------------------------------------------

#[test]
fn a_successful_command_exits_zero() {
    assert_eq!(code(&brolga(&["config", "validate"])), 0);
    assert_eq!(code(&brolga(&["exit-codes"])), 0);
    assert_eq!(code(&brolga(&["--version"])), 0);
}

#[test]
fn a_usage_error_exits_two() {
    // The long-standing convention, and what scripts special-case.
    assert_eq!(code(&brolga(&["teleport"])), 2);
    assert_eq!(code(&brolga(&["--output", "yaml", "doctor"])), 2);
    assert_eq!(code(&brolga(&["--not-a-flag"])), 2);
}

#[test]
fn a_configuration_problem_exits_three() {
    // Distinct from a usage error: the command was well-formed and the fix is in a file.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad.yaml");
    std::fs::write(&path, "limits:\n  max_input_bytes: 0\n").unwrap();

    let output = brolga(&["--config", path.to_str().unwrap(), "config", "validate"]);
    assert_eq!(code(&output), 3);
    assert!(
        stderr(&output).contains("limits.max_input_bytes"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_unimplemented_command_exits_five_and_says_so() {
    for command in ["ingest", "context"] {
        let output = brolga(&[command, "anything"]);
        assert_eq!(code(&output), 5, "{command} must exit 5");

        let message = stderr(&output);
        assert!(message.contains("not implemented"), "{message}");
        assert!(
            message.contains("v0."),
            "the message names a milestone: {message}"
        );
        assert!(
            stdout(&output).is_empty(),
            "an unimplemented command must not print a result",
        );
    }
}

#[test]
fn the_registry_the_binary_reports_matches_the_codes_it_returns() {
    // Exit codes are a compatibility surface. A pipeline author reads them from the build they run,
    // so the listing and the behaviour must agree.
    let listing = brolga(&["--output", "json", "exit-codes"]);
    let codes: Vec<serde_json::Value> = serde_json::from_str(&stdout(&listing)).unwrap();

    let find = |name: &str| {
        codes
            .iter()
            .find(|entry| entry["name"] == name)
            .and_then(|entry| entry["code"].as_i64())
            .unwrap_or_else(|| panic!("{name} is not listed"))
    };

    assert_eq!(find("success"), 0);
    assert_eq!(find("usage"), 2);
    assert_eq!(find("config_invalid"), 3);
    assert_eq!(find("not_implemented"), 5);

    assert_eq!(
        i64::from(code(&brolga(&["config", "validate"]))),
        find("success")
    );
    assert_eq!(i64::from(code(&brolga(&["teleport"]))), find("usage"));
    assert_eq!(
        i64::from(code(&brolga(&["ingest"]))),
        find("not_implemented")
    );
}

// -------------------------------------------------------------------------------------------------
// Secrets
// -------------------------------------------------------------------------------------------------

#[test]
fn a_secret_value_never_reaches_stdout_or_stderr() {
    // The strongest form of the guarantee available end to end: the variable is set in the child's
    // environment with a distinctive value, configuration references it by name, and the value must
    // appear nowhere — not in the result, not in a diagnostic, not at trace level.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.yaml");
    std::fs::write(
        &path,
        "secrets:\n  feed_token:\n    from_env: BROLGA_TEST_SECRET\n",
    )
    .unwrap();

    let canary = "correct-horse-battery-staple-9c1f4b";

    for arguments in [
        vec!["--config", path.to_str().unwrap(), "config", "explain"],
        vec![
            "--config",
            path.to_str().unwrap(),
            "--output",
            "json",
            "--log-level",
            "trace",
            "config",
            "explain",
        ],
        vec!["--config", path.to_str().unwrap(), "config", "validate"],
        vec!["--config", path.to_str().unwrap(), "doctor"],
    ] {
        let output = brolga_with_env(
            &arguments,
            &[("BROLGA_TEST_SECRET", canary), ("BROLGA_LOG", "trace")],
        );

        assert!(
            !stdout(&output).contains(canary),
            "the secret value reached stdout: {}",
            stdout(&output),
        );
        assert!(
            !stderr(&output).contains(canary),
            "the secret value reached stderr: {}",
            stderr(&output),
        );
    }
}

#[test]
fn a_secret_reference_is_shown_so_an_operator_can_see_what_is_configured() {
    // Redacting the *reference* too would leave an operator unable to tell where a value is meant
    // to come from, which is the thing `config explain` exists to answer.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.yaml");
    std::fs::write(
        &path,
        "secrets:\n  feed_token:\n    from_env: BROLGA_TEST_SECRET\n",
    )
    .unwrap();

    let output = brolga(&["--config", path.to_str().unwrap(), "config", "explain"]);
    assert_eq!(code(&output), 0);
    assert!(
        stdout(&output).contains("BROLGA_TEST_SECRET"),
        "{}",
        stdout(&output),
    );
}

#[test]
fn an_inline_secret_in_a_configuration_file_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("inline.yaml");
    std::fs::write(&path, "secrets:\n  feed_token: hunter2\n").unwrap();

    let output = brolga(&["--config", path.to_str().unwrap(), "config", "validate"]);
    assert_eq!(code(&output), 3);
    assert!(stdout(&output).is_empty());
}

// -------------------------------------------------------------------------------------------------
// Commands
// -------------------------------------------------------------------------------------------------

#[test]
fn init_writes_a_file_that_the_binary_then_accepts() {
    // The round trip an operator actually performs. A starter file that does not load is worse than
    // none, because the failure looks like their mistake.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("brolga.yaml");

    let written = brolga(&["init", path.to_str().unwrap()]);
    assert_eq!(code(&written), 0);
    assert!(path.exists());

    let validated = brolga(&["--config", path.to_str().unwrap(), "config", "validate"]);
    assert_eq!(code(&validated), 0, "{}", stderr(&validated));
}

#[test]
fn init_refuses_to_overwrite_without_force() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("brolga.yaml");
    std::fs::write(&path, "version: 1\n").unwrap();

    let refused = brolga(&["init", path.to_str().unwrap()]);
    assert_eq!(code(&refused), 6);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "version: 1\n");
    assert!(stderr(&refused).contains("--force"));

    let forced = brolga(&["init", "--force", path.to_str().unwrap()]);
    assert_eq!(code(&forced), 0);
    assert_ne!(std::fs::read_to_string(&path).unwrap(), "version: 1\n");
}

#[test]
fn doctor_opens_storage_and_reports_the_schema_version() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("brolga.yaml");
    let database = directory.path().join("brolga.sqlite");

    std::fs::write(
        &config,
        format!(
            "storage:\n  sqlite:\n    path: {}\n",
            database.to_str().unwrap()
        ),
    )
    .unwrap();

    let output = brolga(&[
        "--config",
        config.to_str().unwrap(),
        "--output",
        "json",
        "doctor",
    ]);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(parsed["status"], "ok");
    assert!(parsed["correlation_id"].as_str().is_some());

    let checks = parsed["checks"].as_array().unwrap();
    assert!(
        checks.iter().all(|check| check["passed"] == true),
        "{checks:?}"
    );
    assert!(database.exists(), "doctor must have created the database");
}

#[test]
fn config_schema_prints_a_schema_even_when_configuration_is_broken() {
    // Printing the schema must work when the configuration is exactly what the operator is fixing.
    let output = brolga(&["--config", "/does/not/exist.yaml", "config", "schema"]);
    assert_eq!(code(&output), 0);

    let schema: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(
        schema["$id"]
            .as_str()
            .is_some_and(|id| id.contains("brolga.config")),
        "{schema}",
    );
}

#[test]
fn config_explain_reports_which_layer_supplied_each_setting() {
    let directory = tempfile::tempdir().unwrap();
    let site = directory.path().join("site.yaml");
    let host = directory.path().join("host.yaml");
    std::fs::write(&site, "logging:\n  level: debug\n").unwrap();
    std::fs::write(&host, "logging:\n  format: json\n").unwrap();

    let output = brolga(&[
        "--config",
        site.to_str().unwrap(),
        "--config",
        host.to_str().unwrap(),
        "--output",
        "json",
        "config",
        "explain",
        "--changed-only",
    ]);

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let settings = parsed["settings"].as_array().unwrap();

    assert_eq!(settings.len(), 2, "{settings:?}");
    let level = settings
        .iter()
        .find(|setting| setting["path"] == "logging.level")
        .unwrap();
    assert!(
        level["source"].as_str().unwrap().contains("site.yaml"),
        "{level}",
    );
}

#[test]
fn later_configuration_files_override_earlier_ones() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.yaml");
    let second = directory.path().join("second.yaml");
    std::fs::write(&first, "logging:\n  level: debug\n").unwrap();
    std::fs::write(&second, "logging:\n  level: warn\n").unwrap();

    let output = brolga(&[
        "--config",
        first.to_str().unwrap(),
        "--config",
        second.to_str().unwrap(),
        "--output",
        "json",
        "config",
        "explain",
        "--changed-only",
    ]);

    let parsed: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    let level = parsed["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|setting| setting["path"] == "logging.level")
        .unwrap();

    assert_eq!(level["value"], "\"warn\"");
    assert!(level["source"].as_str().unwrap().contains("second.yaml"));
}
