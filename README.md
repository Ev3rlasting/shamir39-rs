# shamir39-rs

[![CI](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/rust.yml)

Split a 24-word BIP-39 mnemonic into Shamir shares and recover it later.

## Security and compatibility

This is experimental software and has not received a security audit. Do not use
it to protect funds or other high-value secrets until it has been independently
reviewed.

`shamir39-rs` shares use the versioned `shamir39-v1` text format. Every share
carries a random group ID, threshold, total share count, index, and BIP-39
language. Recovery rejects shares from different sets, duplicate indices, and
an incorrect number of shares. This format is **not compatible with SLIP-0039**
or with versions of this project before 0.2.0.

The metadata prevents accidental mixing, but it is not an authentication scheme
against a malicious share editor. Keep shares private and verify the recovered
mnemonic before using it.

## Library usage

```rust
use bip39::{Language, Mnemonic};
use shamir39_rs::{combine, split, SplitConfig};

let mnemonic = Mnemonic::from_entropy_in(Language::English, &[7; 32])?;
let shares = split(&mnemonic, SplitConfig {
    threshold: 3,
    share_count: 5,
})?;
let recovered = combine(&shares[..3])?;
assert_eq!(recovered, mnemonic);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Only 24-word mnemonics are accepted. `threshold` must be at least 2 and smaller
than `share_count`; `share_count` is limited to 2048.

## CLI usage

Install from crates.io after publication:

```bash
cargo install shamir39-rs
shamir39-rs
```

The CLI reads existing mnemonics and shares without echoing them. Keep each full
`shamir39-v1:...` line exactly as printed; the line is the complete share.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo publish --dry-run
```

## License

Licensed under [MIT](LICENSE).
