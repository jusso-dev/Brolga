//! The journeys the README documents, run end to end against the real binary.
//!
//! # Why this exists as its own test file
//!
//! A README is a promise, and the usual way a README breaks is not that somebody edits it wrongly —
//! it is that the code moves and nobody re-runs the commands. So the commands are run here, from a
//! clean database, in the order the README gives them, against the fixtures the README names.
//!
//! If a command in `README.md` changes, this file must change with it. That coupling is the point.
//!
//! # Nothing here reaches a network
//!
//! The fixtures are checked in, the addresses are TEST-NET-3 and reserved documentation domains,
//! and no step invokes a connector. The demo is runnable on a machine with no route out — which is
//! the environment a lot of intelligence work actually happens in.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The demo fixtures, resolved from the workspace root rather than the current directory.
fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/demo")
        .join(name)
}

fn brolga(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_brolga"))
        .args(arguments)
        .output()
        .expect("the binary must run")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// **The criterion.** Every command the README gives, from a clean checkout, in order.
///
/// One test rather than several: the journey is the unit. A step that only passes when the previous
/// one did not run is not a journey, and running them separately would let that hide.
#[test]
fn the_readme_quickstart_runs_from_a_clean_database() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let database = directory.path().join("brolga.sqlite");
    let database = database.to_str().expect("a usable path");

    let feed = fixture("feed.json");
    let rule = fixture("rule.yml");

    // 1. Ingest a MISP event and a Sigma rule in one batch. Detection decides the format per file,
    //    so a mixed batch is the ordinary case rather than a special one.
    let ingest = brolga(&[
        "ingest",
        feed.to_str().unwrap(),
        rule.to_str().unwrap(),
        "--mode",
        "permissive",
        "--database",
        database,
    ]);
    assert_eq!(code(&ingest), 0, "{}", stderr(&ingest));
    assert!(stdout(&ingest).contains("accepted"), "{}", stdout(&ingest));

    // 2. Stats: the store now holds records of several kinds.
    let stats = brolga(&["--output", "json", "stats", "--database", database]);
    assert_eq!(code(&stats), 0, "{}", stderr(&stats));
    let counts: serde_json::Value = serde_json::from_str(&stdout(&stats)).expect("JSON stats");
    assert!(
        counts["claims"].as_u64().unwrap_or(0) > 0,
        "the ingest produced no claims: {counts}"
    );
    assert!(
        counts["entities"].as_u64().unwrap_or(0) > 0,
        "the Sigma rule should have produced a detection-rule entity: {counts}"
    );

    // 3. Context: what is known about the address both files mention.
    let context = brolga(&[
        "--output",
        "json",
        "context",
        "ip",
        "203.0.113.42",
        "--database",
        database,
    ]);
    assert_eq!(code(&context), 0, "{}", stderr(&context));
    let pack: serde_json::Value = serde_json::from_str(&stdout(&context)).expect("a JSON pack");

    // The two files meet here. This is what the demo is for: one observable, reached from a feed
    // attribute and a detection rule, because both canonicalise to the same identifier.
    assert_eq!(
        pack["disposition"], "malicious",
        "the MISP `to_ids` flag should have produced a disposition: {pack}"
    );
    assert!(
        !pack["findings"].as_array().unwrap().is_empty(),
        "a finding must cite the evidence behind that disposition: {pack}"
    );

    // 4. The pack expands back to exact source evidence — the criterion that makes the answer
    //    defensible rather than merely present.
    let evidence = pack["findings"][0]["evidence"].as_array().unwrap();
    assert!(!evidence.is_empty(), "{pack}");
    let source_id = evidence[0]["source_object_id"].as_str().unwrap();

    let sources = brolga(&["--output", "json", "sources", "--database", database]);
    assert_eq!(code(&sources), 0, "{}", stderr(&sources));
    assert!(
        stdout(&sources).contains(source_id),
        "the pack cites `{source_id}`, which the retained source objects must include: {}",
        stdout(&sources)
    );

    // 5. Explain-plan: why a pack contains what it does, without needing a pack.
    let plan = brolga(&["--output", "json", "explain-plan", "incident_triage"]);
    assert_eq!(code(&plan), 0, "{}", stderr(&plan));
    let plan: serde_json::Value = serde_json::from_str(&stdout(&plan)).expect("a JSON plan");
    assert!(!plan["plan"].as_array().unwrap().is_empty());
}

/// **The agent journey.** Handshake, list tools, ask about the same observable, and read the
/// evidence back — over the transport an agent runtime actually uses.
#[test]
fn the_mcp_agent_journey_completes_over_stdio() {
    use std::io::Write;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let database = directory.path().join("brolga.sqlite");
    let database = database.to_str().expect("a usable path");

    let feed = fixture("feed.json");
    let ingest = brolga(&[
        "ingest",
        feed.to_str().unwrap(),
        "--mode",
        "permissive",
        "--database",
        database,
    ]);
    assert_eq!(code(&ingest), 0, "{}", stderr(&ingest));

    let mut child = Command::new(env!("CARGO_BIN_EXE_brolga"))
        .args(["mcp", "--database", database])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the MCP server must start");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"brolga_context","arguments":{"kind":"ip","value":"203.0.113.42"}}}"#,
        ] {
            writeln!(stdin, "{line}").expect("write a frame");
        }
        // Closing stdin is how an agent runtime ends a session.
    }

    let output = child.wait_with_output().expect("the server must exit");
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let frames: Vec<serde_json::Value> = stdout(&output)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("each frame is JSON"))
        .collect();

    // Three, not four: the notification is not answered.
    assert_eq!(frames.len(), 3, "{frames:#?}");
    assert!(frames[0]["result"]["protocolVersion"].is_string());
    assert!(!frames[1]["result"]["tools"].as_array().unwrap().is_empty());

    let pack = &frames[2]["result"]["structuredContent"];
    assert_eq!(pack["disposition"], "malicious", "{pack}");
    assert!(
        !pack["handles"].as_array().unwrap().is_empty(),
        "an agent must be handed something it can expand: {pack}"
    );

    // The agent can see what it did *not* get, which is the difference between a compressed answer
    // and a quietly incomplete one.
    assert!(pack["gaps"].is_array());
    assert!(pack["exclusions"].is_array());
    assert!(pack["policy"].is_object());
}

/// **The criterion.** Nothing in the demo reaches a network — no connector, no resolver, no model.
///
/// Asserted over the fixtures rather than by watching syscalls: the addresses are reserved ranges
/// and the only commands the journey runs are local ones. A demo that quietly needed a network
/// would fail in exactly the environment intelligence work happens in.
#[test]
fn the_demo_touches_nothing_outside_the_machine() {
    let feed = std::fs::read_to_string(fixture("feed.json")).expect("the feed fixture");
    let rule = std::fs::read_to_string(fixture("rule.yml")).expect("the rule fixture");

    for (name, body) in [("feed.json", &feed), ("rule.yml", &rule)] {
        // TEST-NET-3 and the reserved documentation domains. Nothing here can resolve or be
        // contacted, so a demo that accidentally grew a fetch would be unable to hide it.
        assert!(
            !body.contains("http://") && !body.contains("https://"),
            "`{name}` names a URL, which a demo fixture should not"
        );
        assert!(
            body.contains("203.0.113.") || body.contains("example."),
            "`{name}` should use reserved ranges only"
        );
    }
}

/// **The mapping journey.** Validate a shipped example, explain it, ingest through it, and reach the
/// result — over the real binary, against the mappings the repository ships.
///
/// One test rather than four: a mapping that validates but cannot ingest, or ingests but produces
/// nothing a lookup can reach, has not done the job. The chain is the unit.
#[test]
fn the_declarative_mapping_journey_runs_end_to_end() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let database = directory.path().join("brolga.sqlite");
    let database = database.to_str().expect("a usable path");

    let mapping =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/mappings/acme-json.yml");
    let mapping = mapping.to_str().expect("a usable path");
    let feed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../brolga-ingest/tests/fixtures/mapping/acme-feed.json");
    let feed = feed.to_str().expect("a usable path");

    // 1. Validate. A mapping that fails here would otherwise fail partway through a document.
    let validate = brolga(&["mapping", "validate", mapping]);
    assert_eq!(code(&validate), 0, "{}", stderr(&validate));
    assert!(
        stdout(&validate).contains("is valid"),
        "{}",
        stdout(&validate)
    );

    // 2. Explain. The refusals are part of the output, not a footnote.
    let explain = brolga(&["mapping", "explain", mapping]);
    assert_eq!(code(&explain), 0, "{}", stderr(&explain));
    let explained = stdout(&explain);
    assert!(explained.contains("subject"), "{explained}");
    assert!(
        explained.contains("this engine will not"),
        "an operator evaluating a mapping from elsewhere needs the refusals: {explained}"
    );

    // 3. Ingest through it.
    let ingest = brolga(&[
        "ingest",
        feed,
        "--mapping",
        mapping,
        "--mode",
        "permissive",
        "--database",
        database,
    ]);
    assert_eq!(code(&ingest), 0, "{}", stderr(&ingest));
    assert!(stdout(&ingest).contains("accepted"), "{}", stdout(&ingest));

    // 4. The mapped indicator is reachable, with the disposition the mapping derived from a
    //    vendor-specific verdict column — which is the whole point of the feature.
    let context = brolga(&[
        "--output",
        "json",
        "context",
        "url",
        "http://evil.example.com/payload",
        "--database",
        database,
    ]);
    assert_eq!(code(&context), 0, "{}", stderr(&context));
    let pack: serde_json::Value = serde_json::from_str(&stdout(&context)).expect("a JSON pack");
    assert_eq!(
        pack["disposition"], "malicious",
        "the mapping's disposition column must reach a context lookup: {pack}"
    );
    assert!(
        !pack["findings"].as_array().unwrap().is_empty(),
        "the answer must cite the evidence behind it: {pack}"
    );
}

/// A mapping pointed at the wrong kind of file fails loudly rather than importing nothing
/// successfully — which is the failure an operator is least likely to notice.
#[test]
fn a_mapping_pointed_at_the_wrong_shape_fails_rather_than_importing_nothing() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let database = directory.path().join("brolga.sqlite");

    let xml_mapping =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/mappings/device-xml.yml");
    let json_feed = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../brolga-ingest/tests/fixtures/mapping/acme-feed.json");

    let ingest = brolga(&[
        "ingest",
        json_feed.to_str().unwrap(),
        "--mapping",
        xml_mapping.to_str().unwrap(),
        "--mode",
        "permissive",
        "--database",
        database.to_str().unwrap(),
    ]);
    assert_ne!(code(&ingest), 0, "{}", stdout(&ingest));
    assert!(
        stderr(&ingest).contains("not the shape") || stdout(&ingest).contains("not the shape"),
        "the reason must name the mismatch: {} / {}",
        stdout(&ingest),
        stderr(&ingest)
    );
}

/// An invalid mapping is a configuration error, not a usage error. A script has to be able to tell
/// "I called this wrongly" from "the operator's mapping is broken".
#[test]
fn an_invalid_mapping_exits_as_a_configuration_error() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("broken.yml");
    std::fs::write(
        &path,
        "schema_version: brolga.mapping/1.0\nid: broken\nsource: json\nrecords: $..value\n\
         fields:\n  - path: v\n    target:\n      type: infer\n    subject: true\n",
    )
    .expect("write the mapping");

    let validate = brolga(&["mapping", "validate", path.to_str().unwrap()]);
    assert_eq!(
        code(&validate),
        3,
        "an invalid mapping is a configuration error: {}",
        stderr(&validate)
    );
    assert!(
        stderr(&validate).contains("recursive descent"),
        "the refusal must name the construct: {}",
        stderr(&validate)
    );
}

/// Plugin manifests: validate a shipped example, explain refusals, reject wildcards as config errors.
#[test]
fn the_plugin_manifest_journey_runs_end_to_end() {
    let manifest =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/parser-manifest.yml");
    let manifest = manifest.to_str().expect("a usable path");

    let validate = brolga(&["plugin", "validate", manifest]);
    assert_eq!(code(&validate), 0, "{}", stderr(&validate));
    assert!(
        stdout(&validate).contains("valid"),
        "validate must say the manifest is valid: {}",
        stdout(&validate)
    );

    let explain = brolga(&["plugin", "explain", manifest]);
    assert_eq!(code(&explain), 0, "{}", stderr(&explain));
    let explained = stdout(&explain);
    assert!(
        explained.contains("refusals") || explained.contains("no native"),
        "explain must surface security refusals: {explained}"
    );
    assert!(
        explained.contains("pure compute") || explained.contains("capabilities"),
        "explain must describe capabilities: {explained}"
    );

    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("evil.yml");
    std::fs::write(
        &path,
        "schema_version: brolga.plugin.manifest/1.0\nname: evil\nversion: 1\napi: \"0.1.0\"\n\
         extension_points:\n  - kind: parser\n    contract_version: \"1.0\"\n\
         capabilities:\n  - kind: network_egress\n    host: \"*\"\n",
    )
    .expect("write the manifest");
    let rejected = brolga(&["plugin", "validate", path.to_str().unwrap()]);
    assert_eq!(
        code(&rejected),
        3,
        "wildcard capability is a configuration error: {}",
        stderr(&rejected)
    );
}

/// The README must say what Brolga cannot do, not only what it can.
///
/// A capability table that lists only what works reads as a claim that everything else works too,
/// and the fastest way to lose a user's trust is for them to find the gap themselves.
#[test]
fn the_readme_states_what_is_not_supported() {
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .expect("the README");

    let lowered = readme.to_lowercase();
    assert!(
        lowered.contains("not supported") || lowered.contains("will not"),
        "the README must make unsupported capabilities explicit"
    );
    // And the demo it documents must exist.
    assert!(
        readme.contains("examples/demo"),
        "the README should point at the checked-in demo fixtures"
    );
}
