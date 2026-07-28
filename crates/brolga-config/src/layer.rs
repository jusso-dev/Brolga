//! Layered configuration, and the record of which layer supplied each setting.
//!
//! # Why the merge happens on values, not on structs
//!
//! Merging typed partial structs would mean writing a field-by-field merge and a field-by-field
//! provenance record for every setting, and forgetting one of them is invisible until an operator
//! asks why a value is what it is.
//!
//! Merging [`serde_json::Value`] instead means the merge is written once, and provenance falls out
//! of it: while merging, the leaf path of every value an overlay supplies is recorded against that
//! overlay. Adding a setting later gets both behaviours with no extra code and no chance of the two
//! disagreeing.
//!
//! The cost is that a layer's *shape* has to be checked separately rather than by the merge — which
//! `load` does, per layer, so that a typo is attributed to the file it came from.
//!
//! # Objects merge, everything else replaces
//!
//! An overlay object is merged key by key. An array, a string, a number, or a null **replaces**
//! whatever was beneath it. Deep-merging arrays would make it impossible to shorten a list, and
//! element-wise merging would make the result depend on ordering an operator never chose.

use core::fmt;
use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::error::ConfigPath;

/// Which layer a value came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LayerId {
    /// Brolga's built-in defaults. Always the lowest layer.
    Defaults,
    /// A configuration file.
    File(String),
    /// The process environment.
    Environment,
    /// Command-line or programmatic overrides. Always the highest layer.
    Overrides,
}

impl LayerId {
    /// A short label for diagnostics and `config explain` output.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Defaults => "defaults".to_owned(),
            Self::File(name) => format!("file:{name}"),
            Self::Environment => "environment".to_owned(),
            Self::Overrides => "overrides".to_owned(),
        }
    }
}

impl fmt::Display for LayerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// One layer's contribution: a partial document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    /// Where the values came from.
    pub id: LayerId,
    /// The values, as a partial document.
    pub values: Value,
}

impl Layer {
    /// Build a layer.
    #[must_use]
    pub const fn new(id: LayerId, values: Value) -> Self {
        Self { id, values }
    }
}

/// Which layer supplied each setting, keyed by dotted path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attribution(BTreeMap<String, LayerId>);

impl Attribution {
    /// An empty attribution.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Which layer supplied a setting.
    #[must_use]
    pub fn source_of(&self, path: &str) -> Option<&LayerId> {
        self.0.get(path)
    }

    /// Every attributed setting, in deterministic path order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &LayerId)> {
        self.0.iter()
    }

    /// How many settings are attributed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing is attributed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn record(&mut self, path: &ConfigPath, layer: &LayerId) {
        self.0.insert(path.as_str().to_owned(), layer.clone());
    }
}

/// Merge layers in order, lowest first, recording which layer supplied each leaf.
///
/// The last layer to write a leaf wins, and is the layer recorded for it. A layer that supplies a
/// value identical to the one beneath it still takes attribution, because the operator did write it
/// there and `config explain` saying otherwise would be misleading.
#[must_use]
pub fn merge_layers(layers: &[Layer]) -> (Value, Attribution) {
    let mut merged = Value::Object(Map::new());
    let mut attribution = Attribution::new();

    for layer in layers {
        merge_value(
            &mut merged,
            &layer.values,
            &layer.id,
            &ConfigPath::root(),
            &mut attribution,
        );
    }

    (merged, attribution)
}

fn merge_value(
    target: &mut Value,
    overlay: &Value,
    layer: &LayerId,
    path: &ConfigPath,
    attribution: &mut Attribution,
) {
    match (&mut *target, overlay) {
        (Value::Object(target_map), Value::Object(overlay_map)) => {
            for (key, overlay_child) in overlay_map {
                let child_path = path.child(key);
                match target_map.get_mut(key) {
                    Some(target_child) => {
                        merge_value(target_child, overlay_child, layer, &child_path, attribution)
                    }
                    None => {
                        target_map.insert(key.clone(), overlay_child.clone());
                        attribute_subtree(overlay_child, layer, &child_path, attribution);
                    }
                }
            }
        }
        // Anything that is not an object-into-object replaces wholesale. See the module docs.
        _ => {
            *target = overlay.clone();
            attribute_subtree(overlay, layer, path, attribution);
        }
    }
}

/// Attribute every leaf under a freshly written value.
fn attribute_subtree(
    value: &Value,
    layer: &LayerId,
    path: &ConfigPath,
    attribution: &mut Attribution,
) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                attribute_subtree(child, layer, &path.child(key), attribution);
            }
        }
        // An empty object is itself a value an operator can write, so it is a leaf. So is an array:
        // arrays replace rather than merge, so attributing per element would imply a granularity
        // the merge does not have.
        _ => attribution.record(path, layer),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file(name: &str, values: Value) -> Layer {
        Layer::new(LayerId::File(name.to_owned()), values)
    }

    #[test]
    fn later_layers_win_and_take_attribution() {
        let (merged, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({"logging": {"level": "info"}})),
            file("brolga.yaml", json!({"logging": {"level": "debug"}})),
        ]);

        assert_eq!(merged["logging"]["level"], json!("debug"));
        assert_eq!(
            attribution.source_of("logging.level"),
            Some(&LayerId::File("brolga.yaml".to_owned())),
        );
    }

    #[test]
    fn a_setting_no_layer_overrode_keeps_its_default_attribution() {
        let (merged, attribution) = merge_layers(&[
            Layer::new(
                LayerId::Defaults,
                json!({"logging": {"level": "info", "format": "text"}}),
            ),
            file("brolga.yaml", json!({"logging": {"level": "debug"}})),
        ]);

        assert_eq!(merged["logging"]["format"], json!("text"));
        assert_eq!(
            attribution.source_of("logging.format"),
            Some(&LayerId::Defaults),
        );
    }

    #[test]
    fn merging_is_deep_for_objects() {
        let (merged, _) = merge_layers(&[
            Layer::new(
                LayerId::Defaults,
                json!({"storage": {"backend": "sqlite", "sqlite": {"path": "a", "busy_timeout_ms": 5000}}}),
            ),
            file("brolga.yaml", json!({"storage": {"sqlite": {"path": "b"}}})),
        ]);

        // The sibling survives: a partial override must not blank out what it did not mention.
        assert_eq!(merged["storage"]["sqlite"]["path"], json!("b"));
        assert_eq!(merged["storage"]["sqlite"]["busy_timeout_ms"], json!(5000));
        assert_eq!(merged["storage"]["backend"], json!("sqlite"));
    }

    #[test]
    fn arrays_replace_rather_than_concatenate() {
        // Deep-merging arrays would make a list impossible to shorten.
        let (merged, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({"tags": ["a", "b", "c"]})),
            file("brolga.yaml", json!({"tags": ["z"]})),
        ]);

        assert_eq!(merged["tags"], json!(["z"]));
        assert_eq!(
            attribution.source_of("tags"),
            Some(&LayerId::File("brolga.yaml".to_owned())),
        );
        assert!(
            attribution.source_of("tags.0").is_none(),
            "arrays replace wholesale, so per-element attribution would imply a granularity the merge does not have"
        );
    }

    #[test]
    fn an_explicit_null_replaces_rather_than_being_ignored() {
        let (merged, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({"logging": {"level": "info"}})),
            file("brolga.yaml", json!({"logging": {"level": null}})),
        ]);

        assert_eq!(merged["logging"]["level"], Value::Null);
        assert_eq!(
            attribution.source_of("logging.level"),
            Some(&LayerId::File("brolga.yaml".to_owned())),
        );
    }

    #[test]
    fn four_layers_apply_lowest_to_highest() {
        let (merged, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({"a": 1, "b": 1, "c": 1, "d": 1})),
            file("brolga.yaml", json!({"b": 2, "c": 2, "d": 2})),
            Layer::new(LayerId::Environment, json!({"c": 3, "d": 3})),
            Layer::new(LayerId::Overrides, json!({"d": 4})),
        ]);

        assert_eq!(merged, json!({"a": 1, "b": 2, "c": 3, "d": 4}));
        assert_eq!(attribution.source_of("a"), Some(&LayerId::Defaults));
        assert_eq!(
            attribution.source_of("b"),
            Some(&LayerId::File("brolga.yaml".to_owned()))
        );
        assert_eq!(attribution.source_of("c"), Some(&LayerId::Environment));
        assert_eq!(attribution.source_of("d"), Some(&LayerId::Overrides));
    }

    #[test]
    fn a_layer_that_restates_a_value_still_takes_attribution() {
        // The operator did write it there, and telling them it came from the defaults would be
        // misleading the next time they change the defaults and nothing happens.
        let (_, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({"logging": {"level": "info"}})),
            file("brolga.yaml", json!({"logging": {"level": "info"}})),
        ]);

        assert_eq!(
            attribution.source_of("logging.level"),
            Some(&LayerId::File("brolga.yaml".to_owned())),
        );
    }

    #[test]
    fn a_new_subtree_attributes_every_leaf_it_introduces() {
        let (_, attribution) = merge_layers(&[
            Layer::new(LayerId::Defaults, json!({})),
            file(
                "brolga.yaml",
                json!({"storage": {"sqlite": {"path": "b", "busy_timeout_ms": 1000}}}),
            ),
        ]);

        assert_eq!(attribution.len(), 2);
        assert!(attribution.source_of("storage.sqlite.path").is_some());
        assert!(
            attribution
                .source_of("storage.sqlite.busy_timeout_ms")
                .is_some()
        );
    }

    #[test]
    fn an_empty_object_is_a_leaf_because_an_operator_can_write_one() {
        let (merged, attribution) =
            merge_layers(&[Layer::new(LayerId::Defaults, json!({"secrets": {}}))]);
        assert_eq!(merged["secrets"], json!({}));
        assert_eq!(attribution.source_of("secrets"), Some(&LayerId::Defaults));
    }

    #[test]
    fn attribution_order_is_deterministic() {
        let build = || {
            merge_layers(&[Layer::new(
                LayerId::Defaults,
                json!({"z": 1, "a": 2, "m": {"y": 3, "b": 4}}),
            )])
            .1
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>()
        };
        assert_eq!(build(), build());
        assert_eq!(build(), vec!["a", "m.b", "m.y", "z"]);
    }

    #[test]
    fn merging_no_layers_yields_an_empty_document() {
        let (merged, attribution) = merge_layers(&[]);
        assert_eq!(merged, json!({}));
        assert!(attribution.is_empty());
    }

    #[test]
    fn layer_labels_are_readable_in_diagnostics() {
        assert_eq!(LayerId::Defaults.to_string(), "defaults");
        assert_eq!(LayerId::Environment.to_string(), "environment");
        assert_eq!(LayerId::Overrides.to_string(), "overrides");
        assert_eq!(
            LayerId::File("/etc/brolga.yaml".to_owned()).to_string(),
            "file:/etc/brolga.yaml",
        );
    }
}
