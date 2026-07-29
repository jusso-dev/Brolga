# Fuzz seeds

Minimal inputs that reach a distinct branch of a parser. They are *seeds*, not fixtures: none of
them is a valid document, and every one of them must be refused or read without an unwind.

They are checked by `tests/property.rs`, which drives each seed through the whole registry, and
they exist as files so a future fuzzing harness ([#56](https://github.com/jusso-dev/Brolga/issues/56))
has a corpus to start from rather than a blank directory.

One file per branch, named for the branch it reaches.
