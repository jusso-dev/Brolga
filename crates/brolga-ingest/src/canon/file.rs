//! File observables: digests, names, and paths.

use brolga_model::ShortText;
use brolga_model::observable::{FileHash, HashAlgorithm, Observable};

use super::{CanonError, Canonical, no_control_characters, trimmed, within};

/// Longest file path accepted before any scan.
///
/// Comfortably above Windows' extended-length limit and POSIX `PATH_MAX`, so a legitimate path is
/// never refused, while a value in the megabytes is.
pub const PATH_MAX_BYTES: usize = 4096;

/// Longest file name accepted before any scan.
pub const FILE_NAME_MAX_BYTES: usize = 255;

/// Which path grammar a value follows.
///
/// The distinction is kept rather than normalised away. `\` is a legal *character in a file name*
/// on POSIX, so rewriting it to `/` invents a directory that never existed; and `C:\x` is not the
/// same object as `/x` under any interpretation. Merging the two families is a data-loss bug that
/// only shows up once two unrelated artefacts share one identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathFlavour {
    /// A POSIX path: `/` separators, case-sensitive, no drive letter.
    Posix,
    /// A Windows path: a drive letter or a UNC prefix, `\` or `/` separators.
    Windows,
}

impl PathFlavour {
    /// A stable label, used in the canonical form so the two families cannot collide.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::Windows => "windows",
        }
    }
}

/// Canonicalise a file digest.
///
/// Accepts a bare hex digest, whose algorithm is inferred from its length, **or** an
/// `algorithm:hex` form such as `sha256:abc…`. Both are common in the wild, and the prefixed form
/// is also the model's own canonical rendering — so re-ingesting Brolga's output has to work, or
/// the round trip is not idempotent. A property test caught exactly that.
///
/// A stated algorithm wins over length inference, because length cannot tell SHA-256 from any other
/// 32-byte digest.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::ForbiddenCharacter`], or [`CanonError::Malformed`] when the
/// value is not hex, names an unknown algorithm, or is not a length any known algorithm produces.
pub fn file_hash(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "FileHash";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;

    let (stated, digits) = match value.split_once(':') {
        Some((prefix, rest)) => (
            Some(algorithm_by_name(prefix).ok_or_else(|| {
                CanonError::malformed(KIND, value, "names an algorithm Brolga does not support")
            })?),
            rest,
        ),
        None => (None, value),
    };

    if let Some(character) = digits.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(CanonError::forbidden(
            KIND,
            value,
            character,
            "a hex digest",
        ));
    }

    let algorithm = match stated {
        Some(algorithm) => algorithm,
        None => algorithm_for_length(digits.len()).ok_or_else(|| {
            CanonError::malformed(KIND, value, "is not the length of any known digest")
        })?,
    };
    let value = digits;

    let hash = FileHash::new(algorithm, value.to_ascii_lowercase())
        .map_err(|_| CanonError::malformed(KIND, value, "is not a valid digest for its length"))?;

    Ok(from_observable(Observable::FileHash(hash), raw))
}

/// Canonicalise a digest whose algorithm the source stated.
///
/// Preferred over [`file_hash`] wherever the format carries the algorithm, because length inference
/// cannot tell SHA-256 from any other 32-byte digest.
///
/// # Errors
///
/// As [`file_hash`], plus a length that disagrees with the stated algorithm.
pub fn file_hash_with_algorithm(
    algorithm: HashAlgorithm,
    raw: &str,
) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "FileHash";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;

    let hash = FileHash::new(algorithm, value.to_ascii_lowercase()).map_err(|_| {
        CanonError::malformed(
            KIND,
            value,
            "is not a valid digest for the stated algorithm",
        )
    })?;

    Ok(from_observable(Observable::FileHash(hash), raw))
}

/// Canonicalise a bare file name.
///
/// Case is preserved: most filesystems Brolga will see indicators from are case-sensitive, and a
/// canonicaliser that lowercases would merge `Invoice.exe` and `invoice.exe`.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`] if the value contains a separator and is therefore a path.
pub fn file_name(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "FileName";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, FILE_NAME_MAX_BYTES)?;

    if value.contains('/') || value.contains('\\') {
        return Err(CanonError::malformed(
            KIND,
            value,
            "contains a separator, so it is a path rather than a name",
        ));
    }

    let text = ShortText::new(value)
        .map_err(|_| CanonError::malformed(KIND, value, "is not a usable short text value"))?;
    Ok(from_observable(Observable::FileName(text), raw))
}

/// Detect which path family a value belongs to.
///
/// Windows if it opens with a drive letter (`C:`) or a UNC prefix (`\\`); otherwise POSIX. A bare
/// `\` elsewhere in the string is **not** enough, because it is a legal character in a POSIX file
/// name and treating it as a separator is exactly the merge this module exists to prevent.
#[must_use]
pub fn path_flavour(raw: &str) -> PathFlavour {
    let bytes = raw.as_bytes();
    let drive_letter = matches!(
        (bytes.first(), bytes.get(1)),
        (Some(letter), Some(b':')) if letter.is_ascii_alphabetic()
    );
    if drive_letter || raw.starts_with("\\\\") || raw.starts_with("//?/") {
        PathFlavour::Windows
    } else {
        PathFlavour::Posix
    }
}

/// Canonicalise a file path, keeping the Windows and POSIX families apart.
///
/// The canonical form is prefixed with the flavour — `posix:/etc/passwd`,
/// `windows:C:\Windows\System32` — so the two can never derive the same identifier however similar
/// they look. Without the prefix, a canonicaliser that normalised separators would map
/// `\etc\passwd` and `/etc/passwd` onto one key, and a Windows share path onto a POSIX absolute
/// path.
///
/// Within each family:
///
/// - **Windows**: the drive letter is uppercased (`c:` and `C:` are the same volume, and Windows
///   itself is case-insensitive here), and `/` separators are rewritten to `\`, which Windows
///   accepts interchangeably. The rest of the path's case is preserved — NTFS stores it, and two
///   files differing only in case are rare but real.
/// - **POSIX**: nothing is rewritten at all. Every byte except `/` and NUL is a legal file-name
///   character, so there is no safe transformation to make.
///
/// Neither family has `.` or `..` resolved. Resolving them requires knowing whether each component
/// is a symlink, which is not knowable from a string, and guessing produces a path that addresses
/// something the source did not name.
///
/// # Errors
///
/// [`CanonError::Empty`], [`CanonError::TooLong`], [`CanonError::ForbiddenCharacter`], or
/// [`CanonError::Malformed`].
pub fn file_path(raw: &str) -> Result<Canonical<Observable>, CanonError> {
    const KIND: &str = "FilePath";
    let value = trimmed(KIND, raw)?;
    no_control_characters(KIND, value)?;
    within(KIND, value, PATH_MAX_BYTES)?;

    let flavour = path_flavour(value);
    let body = match flavour {
        PathFlavour::Posix => value.to_owned(),
        PathFlavour::Windows => canonicalise_windows_path(value),
    };

    let canonical = format!("{}:{body}", flavour.as_str());
    let text = ShortText::new(&canonical)
        .map_err(|_| CanonError::malformed(KIND, value, "is longer than a short text value"))?;

    // Compared against the raw input, which never carries the flavour prefix, so a path always
    // records its original. That is intended: the prefix is Brolga's, not the source's.
    Ok(Canonical::changed(Observable::FilePath(text), raw))
}

/// Uppercase a drive letter and settle on `\` separators.
fn canonicalise_windows_path(value: &str) -> String {
    let with_separators = value.replace('/', "\\");
    let mut characters = with_separators.chars();
    match (characters.next(), with_separators.get(1..2)) {
        (Some(letter), Some(":")) if letter.is_ascii_alphabetic() => {
            let rest: String = characters.collect();
            format!("{}{rest}", letter.to_ascii_uppercase())
        }
        _ => with_separators,
    }
}

/// Resolve an algorithm named in an `algorithm:hex` prefix.
fn algorithm_by_name(name: &str) -> Option<HashAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "md5" => Some(HashAlgorithm::Md5),
        "sha1" | "sha-1" => Some(HashAlgorithm::Sha1),
        "sha256" | "sha-256" => Some(HashAlgorithm::Sha256),
        "sha512" | "sha-512" => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

/// Infer a digest algorithm from its hex length.
const fn algorithm_for_length(hex_length: usize) -> Option<HashAlgorithm> {
    match hex_length {
        32 => Some(HashAlgorithm::Md5),
        40 => Some(HashAlgorithm::Sha1),
        64 => Some(HashAlgorithm::Sha256),
        128 => Some(HashAlgorithm::Sha512),
        _ => None,
    }
}

/// Wrap an observable, comparing against its canonical *value* rather than its `Display`.
fn from_observable(observable: Observable, raw: &str) -> Canonical<Observable> {
    let rendered = observable.canonical_value();
    Canonical::from_parts(observable, &rendered, raw)
}
