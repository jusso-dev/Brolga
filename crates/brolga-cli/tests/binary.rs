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
    assert_eq!(code(&brolga(&["--output", "hieroglyphs", "doctor"])), 2);
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

/// Every declared command is implemented, so nothing exits 5 any more.
///
/// The test that asserted `context` exits 5 is gone rather than repointed: it existed to stop a
/// promise outliving its delivery, and the promise has been delivered. `not_implemented` stays in
/// the exit-code registry below, because a pipeline may already branch on it.
#[test]
fn context_produces_a_pack_rather_than_a_placeholder() {
    // No store, so the pack is about an observable Brolga has never heard of — which is a real
    // answer with a real disposition, not a refusal.
    let directory = tempfile::tempdir().expect("a temporary directory");
    let database = directory.path().join("brolga.sqlite");

    let output = brolga(&[
        "--output",
        "json",
        "context",
        "ip",
        "203.0.113.42",
        "--database",
        database.to_str().unwrap_or("brolga.sqlite"),
    ]);

    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let pack: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("a JSON pack");
    assert_eq!(pack["disposition"], "unknown");
    assert_eq!(pack["subject"]["value"], "203.0.113.42");
    assert!(
        pack["fingerprint"].as_str().is_some_and(|f| !f.is_empty()),
        "a pack must carry its fingerprint"
    );
    assert!(pack["policy"].is_object(), "and its policy context");
}

/// A malformed subject is the caller's mistake, and exits as one.
#[test]
fn a_malformed_context_subject_is_a_usage_error() {
    let output = brolga(&["context", "ip", "not-an-address"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stdout(&output).is_empty(), "no result may be printed");
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
    // Nothing emits `not_implemented` any more, so the registry entry is asserted to exist rather
    // than to be reachable. It stays because a pipeline may already branch on it, and removing a
    // compatibility surface because nothing currently returns it breaks scripts for a reason that
    // has nothing to do with the scripts.
    assert_eq!(i64::from(code(&brolga(&["context"]))), find("usage"));
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

// ---------------------------------------------------------------------------------------------
// The ingest → store → inspect loop, run as a process
// ---------------------------------------------------------------------------------------------

/// A scratch directory holding the fixture corpus, so each test gets its own database.
fn workspace() -> tempfile::TempDir {
    let directory = tempfile::TempDir::new().expect("a scratch directory");
    for name in ["bundle.json", "event.json", "indicators.txt"] {
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
            directory.path().join(name),
        )
        .expect("fixture copied");
    }
    directory
}

/// Run the binary inside a scratch directory.
fn brolga_in(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brolga"))
        .current_dir(directory)
        .args(arguments)
        .output()
        .expect("the brolga binary must run")
}

/// The whole point of this change: a real STIX bundle, a real MISP event, and a plain indicator
/// list go in through the actual binary and come back out as counted records.
#[test]
fn three_real_formats_ingest_through_the_binary_and_are_readable_afterwards() {
    let workspace = workspace();
    let path = workspace.path();

    let ingest = brolga_in(
        path,
        &[
            "ingest",
            "bundle.json",
            "event.json",
            "indicators.txt",
            "--mode",
            "permissive",
        ],
    );
    assert_eq!(code(&ingest), 0, "stderr: {}", stderr(&ingest));
    assert!(stdout(&ingest).contains("permissive ingest:"));

    let stats = brolga_in(path, &["--output", "json", "stats"]);
    assert_eq!(code(&stats), 0);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&stats)).expect("stats must emit one JSON object");

    assert!(
        parsed["entities"].as_u64().unwrap_or(0) > 0,
        "entities landed: {parsed}"
    );
    assert!(parsed["claims"].as_u64().unwrap_or(0) > 0, "{parsed}");
    assert_eq!(
        parsed["source_objects"].as_u64(),
        Some(3),
        "one source object per file: {parsed}"
    );
    assert_eq!(
        parsed["retained_sources"].as_u64(),
        Some(3),
        "the original bytes are retained by default: {parsed}"
    );
}

/// Strict is the default, and it must refuse a corpus containing anything it cannot map rather
/// than importing the readable part.
#[test]
fn strict_is_the_default_and_writes_nothing_when_a_record_cannot_be_accepted() {
    let workspace = workspace();
    let path = workspace.path();

    let ingest = brolga_in(path, &["ingest", "bundle.json"]);
    assert_ne!(code(&ingest), 0, "the bundle holds an unmapped object type");

    let stats = brolga_in(path, &["--output", "json", "stats"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&stats)).unwrap();
    assert_eq!(parsed["entities"].as_u64(), Some(0), "nothing landed");
    assert_eq!(parsed["retained_sources"].as_u64(), Some(0));
}

/// A dry run must exercise the same parsing as a real one and write nothing.
#[test]
fn a_dry_run_reports_what_would_land_and_writes_nothing() {
    let workspace = workspace();
    let path = workspace.path();

    let dry = brolga_in(
        path,
        &["ingest", "bundle.json", "--mode", "permissive", "--dry-run"],
    );
    assert_eq!(code(&dry), 0, "stderr: {}", stderr(&dry));
    assert!(stdout(&dry).contains("nothing written"), "{}", stdout(&dry));

    assert!(
        !path.join("brolga.sqlite").exists(),
        "a dry run must not even create the database"
    );
}

/// Rejections are inspectable afterwards, which is the difference between a quarantine and a log
/// line nobody kept.
#[test]
fn a_quarantined_record_is_readable_from_the_binary_with_its_reason() {
    let workspace = workspace();
    let path = workspace.path();

    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let sources = brolga_in(path, &["--output", "json", "sources"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&sources)).unwrap();
    let digest = parsed["sources"][0]["content_hash"]
        .as_str()
        .expect("a retained source")
        .to_owned();

    let quarantine = brolga_in(path, &["quarantine", "--source", &digest]);
    assert_eq!(code(&quarantine), 0, "stderr: {}", stderr(&quarantine));
    assert!(
        stdout(&quarantine).contains("unsupported_object_type"),
        "the reason category is shown: {}",
        stdout(&quarantine)
    );
    assert!(
        stdout(&quarantine).contains("quarantined rather than coerced"),
        "and the reason itself: {}",
        stdout(&quarantine)
    );
}

/// `show` returns the document as stored, provenance and all — which is what makes a record
/// arguable rather than merely present.
#[test]
fn show_returns_a_stored_record_including_its_provenance() {
    let workspace = workspace();
    let path = workspace.path();

    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    // Find an identifier without reaching into the database: the JSON stats say how many there
    // are, and `sources` gives a source object identifier that `show` must also accept.
    let sources = brolga_in(path, &["--output", "json", "sources"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&sources)).unwrap();
    let id = parsed["sources"][0]["id"]
        .as_str()
        .expect("an id")
        .to_owned();

    let shown = brolga_in(path, &["show", &id]);
    assert_eq!(code(&shown), 0, "stderr: {}", stderr(&shown));
    let record: serde_json::Value =
        serde_json::from_str(&stdout(&shown)).expect("show must emit one JSON object");
    assert_eq!(record["id"].as_str(), Some(id.as_str()));
}

/// The exit-code registry is a compatibility surface, so a script branches on the code rather than
/// on the message. A malformed identifier and a missing record are different problems.
#[test]
fn show_distinguishes_a_malformed_identifier_from_a_missing_record() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "indicators.txt", "--mode", "permissive"]);

    let malformed = brolga_in(path, &["show", "not-an-identifier"]);
    assert_eq!(code(&malformed), 2, "usage");
    assert!(stdout(&malformed).is_empty(), "no result on stdout");

    let missing = brolga_in(
        path,
        &["show", "entity:00000000-0000-0000-0000-000000000000"],
    );
    assert_eq!(code(&missing), 1, "failure, not usage");
    assert!(stdout(&missing).is_empty());
}

/// Re-ingesting the same files must converge rather than accumulate — the normal case for a
/// scheduled import, and the thing that makes a homelab deployment usable rather than growing.
#[test]
fn re_ingesting_the_same_files_converges() {
    let workspace = workspace();
    let path = workspace.path();

    for _ in 0..3 {
        let run = brolga_in(
            path,
            &[
                "ingest",
                "bundle.json",
                "indicators.txt",
                "--mode",
                "permissive",
            ],
        );
        assert_eq!(code(&run), 0, "stderr: {}", stderr(&run));
    }

    let stats = brolga_in(path, &["--output", "json", "stats"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&stats)).unwrap();
    assert_eq!(
        parsed["source_objects"].as_u64(),
        Some(2),
        "two files, three runs, two source objects: {parsed}"
    );
    assert_eq!(
        parsed["quarantine_occurrences"].as_u64(),
        Some(3),
        "the same rejection seen three times is one row counted three times: {parsed}"
    );
}

/// `--output json` must put exactly one object on stdout, whatever commentary is produced.
#[test]
fn ingest_in_json_mode_puts_one_parseable_object_on_stdout() {
    let workspace = workspace();
    let path = workspace.path();

    let ingest = brolga_in(
        path,
        &[
            "--output",
            "json",
            "ingest",
            "bundle.json",
            "--mode",
            "permissive",
        ],
    );
    assert_eq!(code(&ingest), 0, "stderr: {}", stderr(&ingest));

    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&ingest)).expect("stdout must be exactly one JSON object");
    assert_eq!(parsed["mode"].as_str(), Some("permissive"));
    assert_eq!(parsed["reconciles"].as_bool(), Some(true));
}

/// Reading a file that is not there is an I/O problem, not a parse failure, and gets its own code.
#[test]
fn a_missing_input_file_reports_an_io_failure_rather_than_a_parse_failure() {
    let workspace = workspace();
    let missing = brolga_in(workspace.path(), &["ingest", "no-such-file.json"]);

    assert_eq!(code(&missing), 6, "io");
    assert!(stderr(&missing).contains("cannot read"));
    assert!(stdout(&missing).is_empty());
}

// ---------------------------------------------------------------------------------------------
// The user journey #34 asks for, run end to end as a process
// ---------------------------------------------------------------------------------------------

/// #34's first acceptance criterion. Ingest, find, walk, baseline, change, diff — the loop an
/// operator actually performs, through the compiled binary rather than through the library.
#[test]
fn the_example_user_journey_runs_end_to_end() {
    let workspace = workspace();
    let path = workspace.path();

    let ingest = brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);
    assert_eq!(code(&ingest), 0, "stderr: {}", stderr(&ingest));

    // Find something.
    let found = brolga_in(
        path,
        &["--output", "json", "search", "--kind", "intrusion_set"],
    );
    assert_eq!(code(&found), 0);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&found)).unwrap();
    let id = parsed["entities"][0]["id"]
        .as_str()
        .expect("the bundle has an intrusion set")
        .to_owned();

    // Walk out from it.
    let walked = brolga_in(
        path,
        &["--output", "json", "neighbours", &id, "--depth", "2"],
    );
    assert_eq!(code(&walked), 0, "stderr: {}", stderr(&walked));
    let neighbourhood: serde_json::Value = serde_json::from_str(&stdout(&walked)).unwrap();
    assert!(
        neighbourhood["nodes"].as_array().unwrap().len() > 1,
        "the actor is connected to something: {neighbourhood}"
    );
    assert_eq!(
        neighbourhood["complete"].as_bool(),
        Some(true),
        "a small graph within a generous budget is not truncated"
    );

    // Baseline it.
    let took = brolga_in(path, &["checkpoint", "take", "base", "--from", &id]);
    assert_eq!(code(&took), 0, "stderr: {}", stderr(&took));

    let listed = brolga_in(path, &["--output", "json", "checkpoint", "list"]);
    let baselines: serde_json::Value = serde_json::from_str(&stdout(&listed)).unwrap();
    assert_eq!(baselines["checkpoints"].as_array().unwrap().len(), 1);

    // Re-ingest the identical file and take a second baseline. Nothing material changed, so the
    // delta must be empty — this is the property the whole design turns on.
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);
    let again = brolga_in(path, &["checkpoint", "take", "after", "--from", &id]);
    assert_eq!(code(&again), 0);

    let diff = brolga_in(
        path,
        &["--output", "json", "checkpoint", "diff", "base", "after"],
    );
    assert_eq!(code(&diff), 0, "stderr: {}", stderr(&diff));
    let delta: serde_json::Value = serde_json::from_str(&stdout(&diff)).unwrap();
    assert_eq!(
        delta["changes"].as_array().unwrap().len(),
        0,
        "a no-op re-import must produce an empty delta: {delta}"
    );
    assert!(delta["unchanged"].as_u64().unwrap_or(0) > 0);
}

/// A delta that says "changed" without saying *which facet* is not actionable — an operator cannot
/// tell a re-attested source from a renamed actor, and those call for very different responses.
#[test]
fn a_reported_change_names_the_facets_that_moved() {
    let workspace = workspace();
    let path = workspace.path();

    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);
    let found = brolga_in(
        path,
        &["--output", "json", "search", "--kind", "intrusion_set"],
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&found)).unwrap();
    let id = parsed["entities"][0]["id"].as_str().unwrap().to_owned();

    brolga_in(path, &["checkpoint", "take", "base", "--from", &id]);

    // Rewrite the bundle with an extra alias on the intrusion set.
    let source = std::fs::read_to_string(path.join("bundle.json")).unwrap();
    let mut document: serde_json::Value = serde_json::from_str(&source).unwrap();
    for object in document["objects"].as_array_mut().unwrap() {
        if object["type"] == "intrusion-set" {
            object["aliases"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("A-NEW-ALIAS"));
        }
    }
    std::fs::write(
        path.join("bundle-v2.json"),
        serde_json::to_string_pretty(&document).unwrap(),
    )
    .unwrap();

    brolga_in(path, &["ingest", "bundle-v2.json", "--mode", "permissive"]);
    brolga_in(path, &["checkpoint", "take", "mutated", "--from", &id]);

    let diff = brolga_in(
        path,
        &["--output", "json", "checkpoint", "diff", "base", "mutated"],
    );
    assert_eq!(code(&diff), 0, "stderr: {}", stderr(&diff));
    let delta: serde_json::Value = serde_json::from_str(&stdout(&diff)).unwrap();

    let changes = delta["changes"].as_array().unwrap();
    assert!(!changes.is_empty(), "the alias is a material change");

    // The renamed actor names its `names` facet; everything else moved only because it is now
    // attested by a second source object.
    let renamed = changes
        .iter()
        .find(|change| {
            change["facets"]
                .as_array()
                .is_some_and(|facets| facets.iter().any(|facet| facet == "names"))
        })
        .expect("exactly the renamed record names the `names` facet");
    // A `RecordKey` renders as `class/identifier`, so the identifier is a suffix rather than the
    // whole key.
    assert!(
        renamed["record"]
            .as_str()
            .is_some_and(|record| record.ends_with(&id)),
        "the renamed record is the one that was renamed: {}",
        renamed["record"]
    );
    assert!(!renamed["evidence"].as_array().unwrap().is_empty());
}

/// Comparing two baselines taken over different traversals would report records as removed when the
/// narrower one merely did not reach them. Refusing is the point, not a limitation.
#[test]
fn diffing_baselines_of_different_shapes_is_refused_rather_than_answered() {
    let workspace = workspace();
    let path = workspace.path();

    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);
    let found = brolga_in(
        path,
        &["--output", "json", "search", "--kind", "intrusion_set"],
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&found)).unwrap();
    let actor = parsed["entities"][0]["id"].as_str().unwrap().to_owned();

    let malware = brolga_in(
        path,
        &["--output", "json", "search", "--kind", "malware_family"],
    );
    let malware: serde_json::Value = serde_json::from_str(&stdout(&malware)).unwrap();
    let other = malware["entities"][0]["id"].as_str().unwrap().to_owned();

    brolga_in(
        path,
        &["checkpoint", "take", "from-actor", "--from", &actor],
    );
    brolga_in(
        path,
        &["checkpoint", "take", "from-malware", "--from", &other],
    );

    let diff = brolga_in(path, &["checkpoint", "diff", "from-actor", "from-malware"]);
    assert_ne!(
        code(&diff),
        0,
        "differently shaped baselines must be refused"
    );
    assert!(
        stderr(&diff).contains("different traversals"),
        "and must say why: {}",
        stderr(&diff)
    );
    assert!(stdout(&diff).is_empty(), "no result on stdout");
}

/// A filter value that is not in the vocabulary must say what *is*, rather than returning nothing
/// and letting the operator conclude the graph is empty.
#[test]
fn an_unknown_filter_value_lists_the_ones_that_exist() {
    let workspace = workspace();
    let bad = brolga_in(
        workspace.path(),
        &["search", "--kind", "definitely-not-a-kind"],
    );

    assert_eq!(code(&bad), 2, "usage");
    assert!(stdout(&bad).is_empty());
    let message = stderr(&bad);
    assert!(message.contains("threat_actor"), "{message}");
    assert!(message.contains("malware_family"), "{message}");
}

/// Completion is generated from this build's command tree, so it can never advertise a command the
/// binary does not have — which would be worse than no completion, because it reads as
/// documentation.
#[test]
fn completion_is_generated_from_the_command_tree_this_build_actually_has() {
    let workspace = workspace();
    let script = brolga_in(workspace.path(), &["completion", "bash"]);

    assert_eq!(code(&script), 0);
    let rendered = stdout(&script);
    for command in ["ingest", "search", "neighbours", "checkpoint", "stats"] {
        assert!(
            rendered.contains(command),
            "{command} is missing from completion"
        );
    }
    assert!(
        !rendered.contains("compress"),
        "completion must not advertise a command this build does not have"
    );
}

/// A truncated baseline poisons every delta taken against it, so taking one says so loudly rather
/// than as a note that `--quiet` would swallow.
#[test]
fn taking_a_truncated_baseline_warns_on_stderr() {
    let workspace = workspace();
    let path = workspace.path();

    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);
    let found = brolga_in(
        path,
        &["--output", "json", "search", "--kind", "intrusion_set"],
    );
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&found)).unwrap();
    let id = parsed["entities"][0]["id"].as_str().unwrap().to_owned();

    // Depth 1 cannot reach the whole neighbourhood the default would.
    let shallow = brolga_in(
        path,
        &[
            "checkpoint",
            "take",
            "shallow",
            "--from",
            &id,
            "--depth",
            "1",
        ],
    );
    assert_eq!(code(&shallow), 0, "a truncated capture still succeeds");
    assert!(
        stderr(&shallow).contains("truncated"),
        "but it says so: {}",
        stderr(&shallow)
    );
}

// ---------------------------------------------------------------------------------------------
// Output modes — #34's "documented output modes" and "versioned machine schemas"
// ---------------------------------------------------------------------------------------------

/// Every machine-readable mode carries a schema version. A consumer that has to guess whether a
/// field moved has no way to fail safely, and "no version" is indistinguishable from "version 1"
/// until the day it is not.
#[test]
fn every_machine_readable_mode_stamps_a_schema_version() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let json = brolga_in(path, &["--output", "json", "search"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(parsed["schema"].as_str(), Some("brolga.cli.output/1.0"));

    let yaml = brolga_in(path, &["--output", "yaml", "search"]);
    assert!(
        stdout(&yaml).contains("schema: brolga.cli.output/1.0"),
        "{}",
        stdout(&yaml)
    );

    let jsonl = brolga_in(path, &["--output", "jsonl", "search"]);
    for line in stdout(&jsonl)
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let record: serde_json::Value = serde_json::from_str(line).expect("every line is JSON");
        assert_eq!(
            record["schema"].as_str(),
            Some("brolga.cli.output/1.0"),
            "each line is self-describing without its neighbours: {line}"
        );
    }
}

/// JSONL streams the members of a collection, not one object containing an array. A stream a
/// consumer cannot act on until the last element arrives is not a stream.
#[test]
fn jsonl_streams_the_records_rather_than_one_object_containing_them() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let jsonl = brolga_in(path, &["--output", "jsonl", "search"]);
    let rendered = stdout(&jsonl);
    let lines: Vec<&str> = rendered
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();

    assert!(lines.len() > 1, "several records, several lines");
    for line in &lines {
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(record["id"].is_string(), "a record, not a wrapper: {line}");
    }
}

/// The envelope must not overwrite a record's own field. `kind` is a real field on an entity —
/// `intrusion_set` — and an envelope that clobbered it would corrupt the value a consumer filters
/// on, silently.
#[test]
fn the_jsonl_envelope_never_overwrites_a_field_the_record_already_has() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let jsonl = brolga_in(
        path,
        &["--output", "jsonl", "search", "--kind", "intrusion_set"],
    );
    let line = stdout(&jsonl)
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("one intrusion set")
        .to_owned();
    let record: serde_json::Value = serde_json::from_str(&line).unwrap();

    assert_eq!(
        record["kind"].as_str(),
        Some("intrusion_set"),
        "the record's own kind survived: {line}"
    );
    assert_eq!(record["_collection"].as_str(), Some("entities"));
}

/// A table is for eyes. It must line up, and it must not truncate a value to make it line up —
/// a silently shortened identifier is worse than a wide table.
#[test]
fn table_output_aligns_without_truncating_anything() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let table = brolga_in(path, &["--output", "table", "search"]);
    assert_eq!(code(&table), 0);
    let rendered = stdout(&table);

    let lines: Vec<&str> = rendered.lines().collect();
    assert!(lines.len() > 2, "a heading, a rule, and rows");
    assert!(lines[0].contains("ID") && lines[0].contains("NAME"));
    assert!(lines[1].starts_with("---"), "a rule under the heading");

    // Every full identifier is present, not an abbreviation of one.
    let json = brolga_in(path, &["--output", "json", "search"]);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    for entity in parsed["entities"].as_array().unwrap() {
        let id = entity["id"].as_str().unwrap();
        assert!(rendered.contains(id), "{id} was truncated out of the table");
    }
}

/// Human output carries no schema and promises nothing — it may reflow whenever it reads better.
/// Conflating the two is how a script ends up parsing prose.
#[test]
fn human_output_carries_no_schema_version() {
    let workspace = workspace();
    let path = workspace.path();
    brolga_in(path, &["ingest", "bundle.json", "--mode", "permissive"]);

    let human = brolga_in(path, &["search"]);
    assert!(!stdout(&human).contains("brolga.cli.output"));
}
