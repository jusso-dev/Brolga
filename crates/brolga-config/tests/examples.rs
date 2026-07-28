//! The shipped example configurations must actually work.
//!
//! An example that does not validate is worse than no example: an operator copies it, it fails, and
//! the failure looks like *their* mistake. These tests load every file in `examples/` through the
//! real loader, so an example cannot drift from the code that reads it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use brolga_config::layer::{Layer, LayerId};
use brolga_config::load::{Format, parse_layer};
use brolga_config::model::{LogFormat, LogLevel, StorageBackend};
use brolga_config::service::{explain, resolve, validate};

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

fn read(name: &str) -> String {
    let path = examples_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("example {} is unreadable: {error}", path.display()))
}

fn layer_from(name: &str) -> Layer {
    parse_layer(name, &read(name), Format::from_path(name))
        .unwrap_or_else(|error| panic!("example {name} failed to parse: {error}"))
}

fn example_names() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(examples_dir())
        .expect("examples directory must exist")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".yaml") || name.ends_with(".yml") || name.ends_with(".json"))
        .collect();
    names.sort();
    names
}

#[test]
fn every_shipped_example_parses_and_validates() {
    let names = example_names();
    assert!(!names.is_empty(), "no examples found to validate");

    for name in names {
        let layer = layer_from(&name);
        let result = validate(&[layer]);
        assert!(
            result.is_ok(),
            "example {name} does not validate: {}",
            result.unwrap_err(),
        );
    }
}

#[test]
fn the_minimal_example_resolves_to_the_defaults() {
    // It sets only `version`, so everything else must come from the built-in defaults. If this
    // fails, either the defaults changed or the "minimal" example quietly stopped being minimal.
    let resolved = resolve(&[layer_from("minimal.yaml")]).unwrap();
    let defaults = resolve(&[]).unwrap();
    assert_eq!(resolved.config, defaults.config);
    assert_eq!(resolved.fingerprint, defaults.fingerprint);
}

#[test]
fn the_full_example_states_exactly_the_default_values() {
    // `full.yaml` documents the whole surface with the default values, so copying it changes
    // nothing until an operator edits a line. This test is what keeps that claim true.
    let resolved = resolve(&[layer_from("full.yaml")]).unwrap();
    let defaults = resolve(&[]).unwrap();
    assert_eq!(
        resolved.config, defaults.config,
        "full.yaml no longer matches the defaults it claims to document",
    );
}

#[test]
fn the_full_example_mentions_every_setting() {
    // A "full" example that has fallen behind the code is a documentation bug that looks like a
    // working example.
    let explanation = explain(&[]).unwrap();
    let text = read("full.yaml");

    for setting in &explanation.settings {
        let leaf = setting.path.rsplit('.').next().unwrap_or(&setting.path);
        assert!(
            text.contains(leaf),
            "full.yaml does not mention {} (leaf {leaf})",
            setting.path,
        );
    }
}

#[test]
fn the_layered_example_overrides_only_what_it_names() {
    let resolved = resolve(&[layer_from("full.yaml"), layer_from("layered-host.yaml")]).unwrap();

    assert_eq!(resolved.config.logging.level, LogLevel::Debug);
    assert_eq!(resolved.config.logging.format, LogFormat::Json);
    assert_eq!(
        resolved.config.storage.sqlite.path,
        "/var/lib/brolga/brolga.sqlite"
    );

    // Untouched settings keep the value from the layer beneath.
    assert_eq!(resolved.config.storage.backend, StorageBackend::Sqlite);
    assert_eq!(resolved.config.storage.sqlite.busy_timeout_ms, 5000);

    assert_eq!(
        resolved
            .attribution
            .source_of("logging.level")
            .map(LayerId::label),
        Some("file:layered-host.yaml".to_owned()),
    );
    assert_eq!(
        resolved
            .attribution
            .source_of("storage.sqlite.busy_timeout_ms")
            .map(LayerId::label),
        Some("file:full.yaml".to_owned()),
    );
}

#[test]
fn the_secrets_example_holds_references_and_no_values() {
    let resolved = resolve(&[layer_from("secrets.yaml")]).unwrap();
    assert_eq!(resolved.config.secrets.len(), 2);

    let rendered = format!("{:?}", resolved.config.secrets);
    assert!(rendered.contains("BROLGA_FEED_TOKEN"), "{rendered}");
    assert!(rendered.contains("/run/secrets/upstream-key"), "{rendered}");

    // Explaining it names the location and nothing else, because nothing else was ever loaded.
    let explanation = explain(&[layer_from("secrets.yaml")]).unwrap();
    let setting = explanation.get("secrets.feed_token.from_env").unwrap();
    assert_eq!(setting.value, "\"BROLGA_FEED_TOKEN\"");
}

#[test]
fn examples_are_documented_rather_than_bare() {
    // These files are read as documentation as often as they are copied. A bare settings dump
    // teaches nothing about which values are permitted.
    for name in example_names() {
        let text = read(&name);
        assert!(
            text.lines().any(|line| line.trim_start().starts_with('#')),
            "example {name} has no explanatory comments",
        );
    }
}

#[test]
fn an_example_containing_an_inline_secret_would_fail_the_suite() {
    // Guards the guard: proves the suite above would actually catch a bad example rather than
    // passing because nothing is checked.
    let bad = parse_layer("inline.yaml", "secrets:\n  token: hunter2\n", Format::Yaml);

    let failed = match bad {
        Err(_) => true,
        Ok(layer) => validate(&[layer]).is_err(),
    };
    assert!(failed, "an inline secret must not validate");
}
