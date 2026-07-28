//! Canonicalisation tests, one section per acceptance criterion of
//! [#12](https://github.com/jusso-dev/Brolga/issues/12).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use brolga_ingest::CanonError;
use brolga_ingest::canon::{file, ident, net, time};

// ---------------------------------------------------------------------------------------------
// "Unicode and punycode domain forms are retained"
// ---------------------------------------------------------------------------------------------

/// The criterion. The A-label is the key; the Unicode spelling is evidence, and a homograph
/// finding *is* the spelling, so losing it loses the finding.
#[test]
fn a_unicode_domain_keys_on_its_a_label_and_retains_what_the_source_wrote() {
    let canonical = net::domain_name("bücher.example").unwrap();
    assert_eq!(canonical.value().canonical_value(), "xn--bcher-kva.example");
    assert_eq!(canonical.original(), Some("bücher.example"));
}

/// A name already in A-label form must key identically to its Unicode spelling, or the two forms
/// become two records for one domain.
#[test]
fn the_unicode_and_punycode_spellings_of_one_domain_produce_one_key() {
    let unicode = net::domain_name("bücher.example").unwrap();
    let punycode = net::domain_name("xn--bcher-kva.example").unwrap();
    assert_eq!(
        unicode.value().canonical_value(),
        punycode.value().canonical_value()
    );
    assert!(
        !punycode.was_changed(),
        "an already-canonical name retains no redundant original"
    );
}

/// Case and a trailing dot are transport spellings, not distinctions.
#[test]
fn case_and_a_trailing_dot_do_not_make_a_second_domain() {
    let plain = net::domain_name("example.com").unwrap();
    let shouted = net::domain_name("EXAMPLE.COM.").unwrap();
    assert_eq!(
        plain.value().canonical_value(),
        shouted.value().canonical_value()
    );
    assert_eq!(shouted.original(), Some("EXAMPLE.COM."));
}

// ---------------------------------------------------------------------------------------------
// "URL normalisation does not erase meaningful distinctions"
// ---------------------------------------------------------------------------------------------

/// The criterion, stated as the five things that must stay distinct. Each pair is two different
/// resources that a careless canonicaliser would merge into one.
#[test]
fn url_normalisation_keeps_distinctions_that_address_different_resources() {
    let distinct_pairs = [
        (
            "https://example.com/Admin",
            "https://example.com/admin",
            "path case",
        ),
        (
            "https://example.com/a",
            "https://example.com/a/",
            "trailing slash",
        ),
        (
            "https://example.com/?b=2&a=1",
            "https://example.com/?a=1&b=2",
            "query parameter order",
        ),
        (
            "https://example.com/a%2Fb",
            "https://example.com/a/b",
            "percent-encoded separator",
        ),
        (
            "https://example.com/page#one",
            "https://example.com/page#two",
            "fragment",
        ),
    ];

    for (left, right, what) in distinct_pairs {
        let left_key = net::url(left).unwrap().value().canonical_value();
        let right_key = net::url(right).unwrap().value().canonical_value();
        assert_ne!(left_key, right_key, "{what} must stay a distinction");
    }
}

/// The other half: things that genuinely cannot distinguish two resources must be normalised, or
/// one resource becomes several records.
#[test]
fn url_normalisation_does_merge_spellings_that_cannot_differ() {
    let same_pairs = [
        (
            "HTTPS://EXAMPLE.COM/a",
            "https://example.com/a",
            "scheme and host case",
        ),
        (
            "https://example.com:443/a",
            "https://example.com/a",
            "default port",
        ),
    ];

    for (left, right, what) in same_pairs {
        let left_key = net::url(left).unwrap().value().canonical_value();
        let right_key = net::url(right).unwrap().value().canonical_value();
        assert_eq!(left_key, right_key, "{what} is not a distinction");
    }
}

// ---------------------------------------------------------------------------------------------
// "Windows and POSIX paths are not incorrectly merged"
// ---------------------------------------------------------------------------------------------

/// The criterion. `\etc\passwd` and `/etc/passwd` are not the same object under any reading, and a
/// canonicaliser that normalised separators would say they were.
#[test]
fn a_windows_path_and_a_posix_path_never_share_a_key() {
    let windows = file::file_path("C:\\Windows\\System32").unwrap();
    let posix = file::file_path("/Windows/System32").unwrap();
    assert_ne!(
        windows.value().canonical_value(),
        posix.value().canonical_value()
    );
    assert!(windows.value().canonical_value().starts_with("windows:"));
    assert!(posix.value().canonical_value().starts_with("posix:"));
}

/// A backslash is a legal character in a POSIX file name. Treating it as a separator invents a
/// directory that never existed — which is the merge this whole design prevents.
#[test]
fn a_backslash_inside_a_posix_path_is_a_character_not_a_separator() {
    let canonical = file::file_path("/tmp/odd\\name").unwrap();
    assert_eq!(canonical.value().canonical_value(), "posix:/tmp/odd\\name");
}

/// Windows accepts both separators for one path, and the drive letter names one volume either way.
#[test]
fn windows_separators_and_drive_case_are_the_same_path() {
    let back = file::file_path("C:\\Users\\Bob").unwrap();
    let forward = file::file_path("c:/Users/Bob").unwrap();
    assert_eq!(
        back.value().canonical_value(),
        forward.value().canonical_value()
    );
    assert_eq!(back.value().canonical_value(), "windows:C:\\Users\\Bob");
}

/// The rest of a Windows path keeps its case: NTFS stores it, and two files differing only in case
/// are rare but real.
#[test]
fn a_windows_path_keeps_the_case_of_everything_after_the_drive() {
    let canonical = file::file_path("C:\\Users\\Bob\\Invoice.EXE").unwrap();
    assert!(canonical.value().canonical_value().ends_with("Invoice.EXE"));
}

/// Resolving `..` needs to know whether each component is a symlink, which a string cannot say.
/// Guessing produces a path addressing something the source did not name.
#[test]
fn dot_segments_are_left_unresolved_rather_than_guessed() {
    let canonical = file::file_path("/var/www/../etc/passwd").unwrap();
    assert_eq!(
        canonical.value().canonical_value(),
        "posix:/var/www/../etc/passwd"
    );
}

// ---------------------------------------------------------------------------------------------
// "Invalid values fail with typed reasons"
// ---------------------------------------------------------------------------------------------

/// A caller routing to quarantine must be able to branch without matching on prose.
#[test]
fn every_failure_carries_a_typed_reason_and_names_its_kind() {
    let cases: Vec<(&str, CanonError)> = vec![
        ("IpAddress", net::ip_address("999.1.1.1").unwrap_err()),
        ("DomainName", net::domain_name("no-dot").unwrap_err()),
        ("Url", net::url("javascript:alert(1)").unwrap_err()),
        ("EmailAddress", net::email_address("nobody").unwrap_err()),
        ("FileHash", file::file_hash("zzzz").unwrap_err()),
        ("Cve", ident::cve("CVE-14-0160").unwrap_err()),
        ("Cwe", ident::cwe("CWE-").unwrap_err()),
        ("AttackId", ident::attack_id("X1059").unwrap_err()),
        ("Cpe", ident::cpe("cpe:/a:vendor:product").unwrap_err()),
        (
            "PackageUrl",
            ident::package_url("npm/left-pad").unwrap_err(),
        ),
        ("Timestamp", time::rfc3339("not a date").unwrap_err()),
    ];

    for (expected_kind, error) in cases {
        assert_eq!(error.kind(), expected_kind, "wrong kind for {error}");
    }
}

/// An empty value is a distinct condition from a malformed one, and callers treat them
/// differently — an empty field is usually a mapping bug, a malformed one usually bad data.
#[test]
fn an_empty_value_is_a_distinct_error_from_a_malformed_one() {
    assert!(matches!(
        net::domain_name("   ").unwrap_err(),
        CanonError::Empty { .. }
    ));
    assert!(matches!(
        net::domain_name("no-dot").unwrap_err(),
        CanonError::Malformed { .. }
    ));
}

/// The length check must precede the scan, so a hostile megabyte costs a comparison.
#[test]
fn an_oversized_value_is_refused_before_it_is_scanned() {
    let long = format!("{}.com", "a".repeat(net::DOMAIN_MAX_BYTES));
    assert!(matches!(
        net::domain_name(&long).unwrap_err(),
        CanonError::TooLong { .. }
    ));
}

/// Diagnostics reach logs and terminals; an escape sequence must never survive into one.
#[test]
fn a_diagnostic_never_quotes_a_control_character_from_the_input() {
    let error = net::domain_name("evil\u{1b}[31m.example").unwrap_err();
    assert!(matches!(error, CanonError::ForbiddenCharacter { .. }));
    assert!(!error.to_string().contains('\u{1b}'), "{error}");
}

// ---------------------------------------------------------------------------------------------
// "Original values and timezone data remain traceable"
// ---------------------------------------------------------------------------------------------

/// The criterion for timestamps. The offset says where the publisher was, which is part of
/// attributing an observation.
#[test]
fn a_timestamp_normalises_to_utc_and_keeps_the_offset_the_source_wrote() {
    let canonical = time::rfc3339("2026-03-01T09:00:00+10:00").unwrap();
    assert_eq!(canonical.value().to_rfc3339(), "2026-02-28T23:00:00Z");
    assert_eq!(canonical.original(), Some("2026-03-01T09:00:00+10:00"));
}

/// An unchanged value must not carry a copy of itself, or the cases that did change become hard to
/// find among thousands that did not.
#[test]
fn an_original_is_retained_only_when_canonicalisation_changed_something() {
    assert!(!net::ip_address("192.0.2.1").unwrap().was_changed());
    assert!(net::domain_name("EXAMPLE.COM").unwrap().was_changed());
    assert_eq!(
        net::domain_name("EXAMPLE.COM").unwrap().original(),
        Some("EXAMPLE.COM"),
    );
}

// ---------------------------------------------------------------------------------------------
// Canonicalisation choices worth pinning
// ---------------------------------------------------------------------------------------------

/// An IPv4-mapped IPv6 address stays IPv6. Firewalls, allow-lists, and the SSRF checks in
/// `brolga-security` treat the two forms differently, so merging them would defeat those checks.
#[test]
fn an_ipv4_mapped_ipv6_address_is_not_folded_into_ipv4() {
    let mapped = net::ip_address("::ffff:192.0.2.1");
    match mapped {
        Ok(canonical) => assert_ne!(
            canonical.value().canonical_value(),
            "192.0.2.1",
            "the mapped form must not become the bare v4 address"
        ),
        Err(error) => assert!(
            matches!(error, CanonError::Malformed { .. }),
            "refusing it outright is also acceptable; silently folding it is not: {error}"
        ),
    }
}

/// Two spellings of one IPv6 address must reduce to one key.
#[test]
fn ipv6_spellings_reduce_to_one_key() {
    let long = net::ip_address("2001:0DB8:0000:0000:0000:0000:0000:0001").unwrap();
    let short = net::ip_address("2001:db8::1").unwrap();
    assert_eq!(
        long.value().canonical_value(),
        short.value().canonical_value()
    );
    assert!(long.was_changed());
}

/// A range with host bits set is describing the network it is in.
#[test]
fn a_cidr_range_is_masked_to_its_prefix() {
    let sloppy = net::ip_range("192.0.2.5/24").unwrap();
    let exact = net::ip_range("192.0.2.0/24").unwrap();
    assert_eq!(
        sloppy.value().canonical_value(),
        exact.value().canonical_value()
    );
    assert_eq!(sloppy.original(), Some("192.0.2.5/24"));
}

/// The local part belongs to the receiving server. Lowercasing it asserts a policy Brolga cannot
/// know, and merging two mailboxes is worse than keeping two spellings of one.
#[test]
fn an_email_lowercases_the_domain_and_leaves_the_local_part_alone() {
    let canonical = net::email_address("Bob.Smith@EXAMPLE.COM").unwrap();
    assert_eq!(canonical.value().canonical_value(), "Bob.Smith@example.com");
}

/// CVE sequence numbers are not numbers to be tidied. `CVE-2014-160` is not a shorter spelling of
/// `CVE-2014-0160`; it is nothing at all.
#[test]
fn a_cve_uppercases_but_never_strips_leading_zeros_from_the_sequence() {
    let canonical = ident::cve("cve-2014-0160").unwrap();
    assert_eq!(canonical.value(), "CVE-2014-0160");
    assert_eq!(canonical.original(), Some("cve-2014-0160"));
}

/// CWE is the opposite case: MITRE writes them unpadded, so `CWE-079` and `CWE-79` are one
/// weakness written two ways.
#[test]
fn a_cwe_strips_padding_because_mitre_writes_them_unpadded() {
    assert_eq!(ident::cwe("CWE-079").unwrap().value(), "CWE-79");
    assert_eq!(ident::cwe("cwe-79").unwrap().value(), "CWE-79");
}

/// Collapsing a sub-technique to its parent is the difference between a detection and a category.
#[test]
fn an_attack_sub_technique_keeps_its_suffix() {
    assert_eq!(ident::attack_id("t1059.001").unwrap().value(), "T1059.001");
    assert_ne!(
        ident::attack_id("T1059.001").unwrap().value(),
        ident::attack_id("T1059").unwrap().value()
    );
    assert_eq!(ident::attack_id("ta0002").unwrap().value(), "TA0002");
    // Only techniques have sub-techniques.
    assert!(ident::attack_id("TA0002.001").is_err());
}

/// CPE vendor and product are case-sensitive in the specification's matching rules; the closed
/// vocabulary fields are not.
#[test]
fn a_cpe_lowercases_only_the_fields_with_a_closed_vocabulary() {
    let canonical = ident::cpe("CPE:2.3:A:MyVendor:MyProduct:1.0:*:*:*:*:*:*:*").unwrap();
    assert!(canonical.value().starts_with("cpe:2.3:a:"));
    assert!(
        canonical.value().contains("MyVendor:MyProduct"),
        "vendor and product keep their case: {}",
        canonical.value()
    );
}

/// Expanding the default registry or the `latest` tag would bake one client's configuration into
/// stored intelligence.
#[test]
fn a_container_image_lowercases_the_name_but_invents_no_registry_or_tag() {
    let canonical = ident::container_image("Docker.IO/Library/Alpine:3.19").unwrap();
    assert_eq!(canonical.value(), "docker.io/library/alpine:3.19");

    let bare = ident::container_image("alpine").unwrap();
    assert_eq!(bare.value(), "alpine", "no registry and no tag invented");
}

/// A registry port is not a tag. Getting this wrong silently splits every image from a private
/// registry into two.
#[test]
fn a_registry_port_is_not_mistaken_for_a_tag() {
    let canonical = ident::container_image("registry.example:5000/app:v1").unwrap();
    assert_eq!(canonical.value(), "registry.example:5000/app:v1");
}

/// S3 object keys and IAM paths are case-sensitive; the ARN's leading fields are not.
#[test]
fn an_arn_lowercases_its_leading_fields_and_preserves_the_resource() {
    let canonical = ident::cloud_resource("ARN:AWS:S3:::My-Bucket/Path/To/Object.TXT").unwrap();
    assert!(canonical.value().starts_with("arn:aws:s3:::"));
    assert!(
        canonical.value().ends_with("My-Bucket/Path/To/Object.TXT"),
        "the resource keeps its case: {}",
        canonical.value()
    );
}

/// A digest may arrive bare or as `algorithm:hex` — both are common, and the prefixed form is the
/// model's own canonical rendering, so re-ingesting Brolga's output has to work. A property test
/// found this by feeding one canonicaliser's output back into it.
#[test]
fn a_digest_is_accepted_bare_or_algorithm_prefixed_and_both_give_one_key() {
    let bare = file::file_hash("D41D8CD98F00B204E9800998ECF8427E").unwrap();
    let prefixed = file::file_hash("md5:d41d8cd98f00b204e9800998ecf8427e").unwrap();
    assert_eq!(
        bare.value().canonical_value(),
        prefixed.value().canonical_value()
    );
    assert!(bare.was_changed(), "the uppercase spelling is retained");
}

/// A stated algorithm must win over length inference, which cannot tell SHA-256 from any other
/// 32-byte digest.
#[test]
fn a_stated_algorithm_is_believed_over_the_length() {
    let error = file::file_hash("sha256:d41d8cd98f00b204e9800998ecf8427e").unwrap_err();
    assert!(
        matches!(error, CanonError::Malformed { .. }),
        "a 32-hex value stated as SHA-256 is a contradiction, not a silently re-labelled MD5: {error}"
    );
}

/// Leading zeros in an IPv4 octet are refused rather than interpreted. `010` is 8 in octal and 10
/// in decimal depending on who parses it, and that disagreement is a real allow-list bypass — so
/// the ambiguous spelling is rejected instead of resolved one way.
#[test]
fn an_ipv4_octet_with_leading_zeros_is_refused_rather_than_guessed() {
    let error = net::ip_address("192.000.002.001").unwrap_err();
    assert!(matches!(error, CanonError::Malformed { .. }), "{error}");
    assert!(
        net::ip_address("192.0.2.1").is_ok(),
        "the unambiguous form is fine"
    );
}
