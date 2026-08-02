# shamir39-rs

[![CI](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/shamir39-rs.svg)](https://crates.io/crates/shamir39-rs)

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

## CLI walkthrough

The following is a public test vector generated with the CLI. It is included to
show the complete format and **must never be used as a wallet mnemonic**.

Create five shares with a recovery threshold of three:

```text
$ shamir39-rs
Select share language:
1. English
2. Simplified Chinese
...
Language number: 1
Choose an option:
1. Generate a new 24-word mnemonic and split it
2. Split an existing 24-word mnemonic
3. Recover a mnemonic from shares
4. Convert a mnemonic to a target language
Choose an option: 1
Original mnemonic: vacuum brown essence rapid pool rebuild salad select already rapid jelly sense host person route burst lyrics clump heavy holiday security expire purpose bicycle
Recovery threshold: 3
Total number of shares: 5
Generated shares (keep the full line for each share):
shamir39-v1:1f19a77382f719aca84635979c9526d5:3:5:1:en:05e4732c:gaze noble mutual learn damage celery program grief identify satisfy wise stone sunny drastic ribbon cable portion thing awful trophy tragic trust luggage window
shamir39-v1:1f19a77382f719aca84635979c9526d5:3:5:2:en:0cccd028:property priority mansion jewel fox sunset cactus portion list visual ceiling amazing forum gloom promote snack stove harsh kiwi fortune candy prize alpha slab
shamir39-v1:1f19a77382f719aca84635979c9526d5:3:5:3:en:4575eec9:stable fresh coach output blossom spawn bracket mass diagram fame valve fix visual allow normal chaos aware shock price settle limb news dust solar
shamir39-v1:1f19a77382f719aca84635979c9526d5:3:5:4:en:ead45736:stove private liquid upset heart apology order already panther subway genius shrug pink clown item clock fetch waste over cat anchor polar develop woman
shamir39-v1:1f19a77382f719aca84635979c9526d5:3:5:5:en:f02873f6:release normal marriage hood fan manage piano cattle prize magnet input fever hire squeeze evoke symptom pizza word fiber just release tiger useful define
```

Recovering with any three unique shares from the same group returns the original
mnemonic. The share entries are hidden while they are typed:

```text
$ shamir39-rs
Select share language:
...
Language number: 1
Choose an option: 3
Number of shares to provide: 3
Share 1:
Share 2:
Share 3:
Recovered mnemonic: vacuum brown essence rapid pool rebuild salad select already rapid jelly sense host person route burst lyrics clump heavy holiday security expire purpose bicycle
```

For real use, record every full share line exactly as emitted. The group ID,
threshold, total count, index, language, and checksum are all validated during
recovery.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo publish --dry-run
```

## License

Licensed under [MIT](LICENSE).
