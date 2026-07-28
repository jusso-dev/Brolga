//! Property tests for identifier derivation, canonicalisation, and serialisation.
//!
//! The unit tests in each module check the cases a human thought of. These check the invariants
//! that must hold for *every* input, including the ones nobody thought of — which is where
//! canonicalisation bugs actually live.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_model::claim::{Assertion, Claim};
use brolga_model::confidence::ConfidenceScore;
use brolga_model::entity::{Entity, EntityKind};
use brolga_model::id::{Id, Identifiable};
use brolga_model::observable::{
    CanonicalUrl, DomainName, EmailAddress, FileHash, HashAlgorithm, IpRange, MacAddress,
    Observable,
};
use brolga_model::provenance::{
    ContentHash, Provenance, RecordOrigin, SourceObject, SyntheticOrigin, SyntheticReason,
    TransformationChain, TransformationStage, TransformationStep,
};
use brolga_model::relationship::NodeRef;
use brolga_model::status::Disposition;
use brolga_model::temporal::Timestamp;
use brolga_model::text::{ShortText, UntrustedText};
use proptest::prelude::*;

/// A synthetic origin for property tests.
fn test_origin() -> RecordOrigin {
    RecordOrigin::synthetic(SyntheticOrigin::new(
        SyntheticReason::Fixture,
        ShortText::new("brolga-model-property-tests").expect("valid creator"),
    ))
}

/// A generator for syntactically valid DNS names.
///
/// The final label starts with a letter, because an all-numeric top-level label is rejected as
/// ambiguous with an IPv4 address.
fn any_domain_name() -> impl Strategy<Value = String> {
    (
        proptest::collection::vec("[a-zA-Z0-9]{1,20}", 1..4),
        "[a-zA-Z][a-zA-Z0-9]{1,10}",
    )
        .prop_map(|(mut labels, tld)| {
            labels.push(tld);
            labels.join(".")
        })
}

/// A generator for arbitrary observables, covering every variant.
fn any_observable() -> impl Strategy<Value = Observable> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| Observable::Ipv4Address(octets.into())),
        any_domain_name().prop_map(|name| Observable::DomainName(DomainName::new(name).unwrap())),
        (any_domain_name(), "[a-zA-Z0-9._-]{1,30}").prop_map(|(domain, path)| {
            Observable::Url(CanonicalUrl::new(format!("https://{domain}/{path}")).unwrap())
        }),
        (any_domain_name(), "[a-zA-Z0-9._-]{1,30}").prop_map(|(domain, local)| {
            Observable::EmailAddress(EmailAddress::new(format!("{local}@{domain}")).unwrap())
        }),
        "[0-9a-fA-F]{64}".prop_map(|digest| {
            Observable::FileHash(FileHash::new(HashAlgorithm::Sha256, digest).unwrap())
        }),
        any::<[u8; 6]>().prop_map(|octets| {
            let rendered = octets
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            Observable::MacAddress(MacAddress::new(rendered).unwrap())
        }),
        any::<u32>().prop_map(Observable::AutonomousSystemNumber),
        "[a-zA-Z0-9._-]{1,60}".prop_map(|name| Observable::FileName(ShortText::new(name).unwrap())),
    ]
}

proptest! {
    #[test]
    fn every_observable_round_trips_through_json(observable in any_observable()) {
        let json = serde_json::to_string(&observable).unwrap();
        let back: Observable = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, observable);
    }

    #[test]
    fn observable_identifiers_are_a_function_of_the_value(observable in any_observable()) {
        // Same value, same identifier, every time. This is what makes re-import idempotent.
        prop_assert_eq!(observable.id(), observable.id());

        // And the identifier survives a serialisation round trip, so an identifier computed
        // before storage matches one computed after retrieval.
        let json = serde_json::to_string(&observable).unwrap();
        let back: Observable = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back.id(), observable.id());
    }

    #[test]
    fn distinct_observable_values_get_distinct_identifiers(
        left in any_observable(),
        right in any_observable(),
    ) {
        if left != right {
            prop_assert_ne!(left.id(), right.id());
        }
    }

    #[test]
    fn domain_canonicalisation_is_idempotent(name in any_domain_name()) {
        let once = DomainName::new(&name).unwrap();
        let twice = DomainName::new(once.as_str()).unwrap();
        prop_assert_eq!(&once, &twice);

        // Case and a trailing dot are representation, not identity.
        let noisy = DomainName::new(format!("{}.", name.to_uppercase())).unwrap();
        prop_assert_eq!(once, noisy);
    }

    #[test]
    fn hash_case_folding_is_idempotent(digest in "[0-9a-fA-F]{64}") {
        let once = FileHash::new(HashAlgorithm::Sha256, &digest).unwrap();
        let twice = FileHash::new(HashAlgorithm::Sha256, once.value()).unwrap();
        prop_assert_eq!(&once, &twice);
        prop_assert_eq!(once.value(), digest.to_lowercase());
    }

    #[test]
    fn mac_rendering_is_canonical_regardless_of_input_style(octets in any::<[u8; 6]>()) {
        let colons = octets.iter().map(|o| format!("{o:02X}")).collect::<Vec<_>>().join(":");
        let hyphens = octets.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().join("-");
        prop_assert_eq!(
            MacAddress::new(colons).unwrap(),
            MacAddress::new(hyphens).unwrap(),
        );
    }

    #[test]
    fn identifier_derivation_never_confuses_part_boundaries(
        left in ".{0,40}",
        right in ".{0,40}",
    ) {
        // The classic bug this guards against: joining parts with a separator that can appear in
        // the data, so ("a:b", "c") and ("a", "b:c") collide.
        let split_one = Id::<Entity>::derive(&[&left, &right]);
        let joined = format!("{left}{right}");
        let split_none = Id::<Entity>::derive(&[&joined]);
        if !right.is_empty() {
            prop_assert_ne!(split_one, split_none);
        }
    }

    #[test]
    fn identifiers_round_trip_through_their_string_form(parts in proptest::collection::vec(".{0,20}", 0..4)) {
        let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
        let id = Id::<Entity>::derive(&refs);
        let rendered = id.to_string();
        let expected_prefix = format!("{}:", Entity::ID_KIND);
        prop_assert!(rendered.starts_with(&expected_prefix));
        prop_assert_eq!(Id::<Entity>::parse(&rendered).unwrap(), id);
    }

    #[test]
    fn bounded_text_accepts_exactly_what_it_documents(value in ".{0,600}") {
        let result = ShortText::new(&value);
        let expected_ok = !value.is_empty()
            && value.len() <= ShortText::MAX_BYTES
            && !value.chars().any(char::is_control);
        prop_assert_eq!(result.is_ok(), expected_ok, "for {:?}", value);
    }

    #[test]
    fn untrusted_text_round_trips_verbatim(value in "[a-zA-Z0-9 .,:;_\\-\n\t]{0,200}") {
        let text = UntrustedText::new(&value).unwrap();
        let json = serde_json::to_string(&text).unwrap();
        let back: UntrustedText = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back.as_str(), value.as_str());
    }

    #[test]
    fn timestamps_round_trip_through_rfc3339(seconds in -62_135_596_800_i64..253_402_300_799_i64) {
        let instant = time::OffsetDateTime::from_unix_timestamp(seconds).unwrap();
        let timestamp = Timestamp::from_offset_date_time(instant);
        let rendered = timestamp.to_rfc3339();
        prop_assert_eq!(Timestamp::parse_rfc3339(&rendered).unwrap(), timestamp);
        prop_assert_eq!(timestamp.unix_timestamp(), seconds);
    }

    #[test]
    fn confidence_scores_accept_exactly_zero_through_one_hundred(value in any::<u8>()) {
        prop_assert_eq!(ConfidenceScore::new(value).is_ok(), value <= 100);
    }

    #[test]
    fn ip_ranges_reject_every_set_host_bit(octets in any::<[u8; 4]>(), prefix in 0_u8..=32) {
        let address = core::net::Ipv4Addr::from(octets);
        let bits = u32::from_be_bytes(octets);
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
        let is_network_address = bits & !mask == 0;

        prop_assert_eq!(
            IpRange::new(address.into(), prefix).is_ok(),
            is_network_address,
        );
    }

    #[test]
    fn claims_derive_one_identifier_per_distinct_statement(
        domain in any_domain_name(),
        disposition in prop_oneof![
            Just(Disposition::Malicious),
            Just(Disposition::Suspicious),
            Just(Disposition::Benign),
            Just(Disposition::AllowListed),
            Just(Disposition::Unknown),
        ],
    ) {
        let subject = NodeRef::Observable(
            Observable::DomainName(DomainName::new(&domain).unwrap()).id(),
        );
        let first = Claim::new(subject, Assertion::Disposition(disposition), test_origin());
        let second = Claim::new(subject, Assertion::Disposition(disposition), test_origin());
        prop_assert_eq!(first.id, second.id);

        let json = serde_json::to_string(&first).unwrap();
        let back: Claim = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, first);
    }

    #[test]
    fn entity_identity_ignores_the_name_entirely(
        authority in "[a-z][a-z0-9-]{0,20}",
        external_id in "[A-Za-z0-9]{1,20}",
        name_a in "[a-zA-Z0-9 ._-]{1,40}",
        name_b in "[a-zA-Z0-9 ._-]{1,40}",
    ) {
        let authority = ShortText::new(authority).unwrap();
        let external_id = ShortText::new(external_id).unwrap();
        let id = Entity::derive_id(EntityKind::ThreatActor, &authority, &external_id);

        // Two entities with the same authority identifier are the same record whatever they are
        // called, and the roadmap forbids the converse: merging on name similarity.
        let first = Entity::new(id, EntityKind::ThreatActor, UntrustedText::new(name_a).unwrap(), test_origin());
        let second = Entity::new(id, EntityKind::ThreatActor, UntrustedText::new(name_b).unwrap(), test_origin());
        prop_assert_eq!(first.id, second.id);

        let json = serde_json::to_string(&first).unwrap();
        let back: Entity = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(back, first);
    }
}

// Arbitrary bytes must never produce a valid canonical value by accident, and must never panic.
// This is the property that matters most for hostile input: the failure mode has to be a
// rejection, not a crash and not a silently mangled value. Run with more cases than the default,
// because the interesting inputs here are rare.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn hostile_strings_are_rejected_rather_than_mangled_or_panicking(raw in ".{0,120}") {
        // Each of these either returns a value it can re-render identically, or an error.
        if let Ok(domain) = DomainName::new(&raw) {
            prop_assert_eq!(DomainName::new(domain.as_str()).unwrap(), domain);
        }
        if let Ok(email) = EmailAddress::new(&raw) {
            prop_assert_eq!(EmailAddress::new(email.to_string()).unwrap(), email);
        }
        if let Ok(url) = CanonicalUrl::new(&raw) {
            prop_assert_eq!(CanonicalUrl::new(url.as_str()).unwrap(), url);
        }
        if let Ok(mac) = MacAddress::new(&raw) {
            prop_assert_eq!(MacAddress::new(mac.to_string()).unwrap(), mac);
        }
        if let Ok(range) = IpRange::parse(&raw) {
            prop_assert_eq!(IpRange::parse(&range.to_string()).unwrap(), range);
        }
        if let Ok(timestamp) = Timestamp::parse_rfc3339(&raw) {
            prop_assert_eq!(Timestamp::parse_rfc3339(&timestamp.to_rfc3339()).unwrap(), timestamp);
        }
    }

    #[test]
    fn arbitrary_json_never_panics_a_deserialiser(raw in ".{0,200}") {
        // Deserialisation of untrusted bytes must fail, not abort the process.
        let _ = serde_json::from_str::<Observable>(&raw);
        let _ = serde_json::from_str::<Entity>(&raw);
        let _ = serde_json::from_str::<Claim>(&raw);
        let _ = serde_json::from_str::<brolga_model::relationship::Relationship>(&raw);
        let _ = serde_json::from_str::<brolga_model::sighting::Sighting>(&raw);
    }
}

proptest! {
    #[test]
    fn content_hashing_is_deterministic_and_injective(
        left in proptest::collection::vec(any::<u8>(), 0..512),
        right in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        prop_assert_eq!(ContentHash::of(&left), ContentHash::of(&left));
        if left != right {
            prop_assert_ne!(ContentHash::of(&left), ContentHash::of(&right));
        }
    }

    #[test]
    fn content_hashes_round_trip_through_their_string_form(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let hash = ContentHash::of(&bytes);
        let rendered = hash.to_string();
        prop_assert!(rendered.starts_with("sha256:"));
        prop_assert_eq!(ContentHash::parse(&rendered).unwrap(), hash);
        prop_assert_eq!(
            serde_json::from_str::<ContentHash>(&serde_json::to_string(&hash).unwrap()).unwrap(),
            hash,
        );
    }

    #[test]
    fn source_objects_are_addressed_by_content_alone(
        bytes in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        // Two imports of identical bytes must be one source object, whatever route they arrived by.
        let hash = ContentHash::of(&bytes);
        prop_assert_eq!(SourceObject::derive_id(hash), SourceObject::derive_id(hash));
    }

    #[test]
    fn a_transformation_chain_fingerprint_ignores_the_clock(
        versions in proptest::collection::vec(any::<u32>(), 1..8),
        seconds in 0_i64..1_000_000_000,
    ) {
        let build = |stamped: bool| {
            let steps = versions
                .iter()
                .map(|version| {
                    let mut step = TransformationStep::new(
                        TransformationStage::Enrichment,
                        ShortText::new("brolga.enrich.x").unwrap(),
                        *version,
                    );
                    if stamped {
                        step.performed_at = Some(Timestamp::from_offset_date_time(
                            time::OffsetDateTime::from_unix_timestamp(seconds).unwrap(),
                        ));
                    }
                    step
                })
                .collect();
            TransformationChain::new(steps).unwrap()
        };

        prop_assert_eq!(build(false).fingerprint(), build(true).fingerprint());
    }

    #[test]
    fn provenance_round_trips_and_keeps_every_original(
        originals in proptest::collection::vec(
            ("[a-z][a-z0-9_.]{0,20}", "[a-zA-Z0-9 .,:;+_/@-]{0,60}"),
            0..8,
        ),
    ) {
        let source = SourceObject::derive_id(ContentHash::of(b"bundle"));
        let chain = TransformationChain::new(vec![TransformationStep::new(
            TransformationStage::Canonicalisation,
            ShortText::new("brolga.canonicalise.x").unwrap(),
            1,
        )])
        .unwrap();

        let mut provenance = Provenance::from_source(source, chain).unwrap();
        for (field, original) in &originals {
            provenance
                .record_original(
                    &ShortText::new(field.clone()).unwrap(),
                    UntrustedText::new(original.clone()).unwrap(),
                )
                .unwrap();
        }

        let json = serde_json::to_string(&provenance).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(&back, &provenance);

        for (field, original) in &originals {
            // Later duplicates of the same field name legitimately overwrite earlier ones, so only
            // the last write for each key is asserted.
            let expected = originals
                .iter()
                .rfind(|(candidate, _)| candidate == field)
                .map(|(_, value)| value.as_str());
            prop_assert_eq!(
                back.original.get(field).map(|text| text.as_str()),
                expected,
                "original for {} was lost; wrote {}",
                field,
                original,
            );
        }
    }
}
