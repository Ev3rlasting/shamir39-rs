//! Share and recover BIP-39 mnemonics.
//!
//! This crate uses a versioned, self-describing share format. It is not
//! compatible with SLIP-0039 and should not be presented as such.

use std::{fmt, str::FromStr};

use bip39::{Language, Mnemonic};
use num_bigint::{BigInt, Sign};
use shamir_secret_sharing::ShamirSecretSharing as Sss;

const PRIME_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const ENTROPY_BYTES: usize = 32;
const MAX_SHARES: usize = 2048;

/// Configuration for one share set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplitConfig {
    /// Number of shares required for recovery.
    pub threshold: usize,
    /// Number of shares to create.
    pub share_count: usize,
}

/// A versioned share that includes the data required to validate a share set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Share {
    group_id: [u8; 16],
    threshold: usize,
    share_count: usize,
    index: usize,
    language: Language,
    mnemonic: Mnemonic,
}

impl Share {
    /// Returns the share-set identifier.
    pub fn group_id(&self) -> [u8; 16] {
        self.group_id
    }

    /// Returns the number of shares required for recovery.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the total number of shares in the set.
    pub fn share_count(&self) -> usize {
        self.share_count
    }

    /// Returns this share's one-based Shamir index.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the BIP-39 language used to encode this share.
    pub fn language(&self) -> Language {
        self.language
    }
}

/// Errors returned while creating, parsing, or recovering shares.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    InvalidConfig,
    SecretOutsideField,
    InvalidShareFormat,
    InvalidShareMnemonic,
    MixedShareSets,
    DuplicateShareIndex,
    WrongShareCount { expected: usize, actual: usize },
    RecoveredSecretInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => write!(
                f,
                "threshold must be at least 2 and smaller than share_count (at most {MAX_SHARES})"
            ),
            Self::SecretOutsideField => write!(f, "mnemonic entropy is outside the Shamir field"),
            Self::InvalidShareFormat => write!(f, "invalid shamir39 share format"),
            Self::InvalidShareMnemonic => {
                write!(f, "share mnemonic is invalid for its declared language")
            }
            Self::MixedShareSets => write!(f, "shares do not belong to the same share set"),
            Self::DuplicateShareIndex => write!(f, "duplicate share index"),
            Self::WrongShareCount { expected, actual } => {
                write!(f, "expected exactly {expected} shares, received {actual}")
            }
            Self::RecoveredSecretInvalid => {
                write!(f, "recovered secret is not valid 256-bit BIP-39 entropy")
            }
        }
    }
}

impl std::error::Error for Error {}

impl fmt::Display for Share {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shamir39-v1:{}:{}:{}:{}:{}:{:08x}:{}",
            hex_encode(&self.group_id),
            self.threshold,
            self.share_count,
            self.index,
            language_code(self.language),
            share_checksum(self),
            self.mnemonic,
        )
    }
}

impl FromStr for Share {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.trim().splitn(8, ':');
        if fields.next() != Some("shamir39-v1") {
            return Err(Error::InvalidShareFormat);
        }
        let group_id = decode_group_id(fields.next().ok_or(Error::InvalidShareFormat)?)?;
        let threshold = parse_usize(fields.next())?;
        let share_count = parse_usize(fields.next())?;
        let index = parse_usize(fields.next())?;
        validate_config(SplitConfig {
            threshold,
            share_count,
        })?;
        if !(1..=share_count).contains(&index) {
            return Err(Error::InvalidShareFormat);
        }
        let language = parse_language(fields.next().ok_or(Error::InvalidShareFormat)?)?;
        let checksum = u32::from_str_radix(fields.next().ok_or(Error::InvalidShareFormat)?, 16)
            .map_err(|_| Error::InvalidShareFormat)?;
        let mnemonic =
            Mnemonic::parse_in(language, fields.next().ok_or(Error::InvalidShareFormat)?)
                .map_err(|_| Error::InvalidShareMnemonic)?;
        if mnemonic.to_entropy().len() != ENTROPY_BYTES {
            return Err(Error::InvalidShareMnemonic);
        }

        let share = Self {
            group_id,
            threshold,
            share_count,
            index,
            language,
            mnemonic,
        };
        if checksum != share_checksum(&share) {
            return Err(Error::InvalidShareFormat);
        }
        Ok(share)
    }
}

/// Splits a 24-word BIP-39 mnemonic into self-describing shares.
pub fn split(mnemonic: &Mnemonic, config: SplitConfig) -> Result<Vec<Share>, Error> {
    validate_config(config)?;
    let secret_bytes = mnemonic.to_entropy();
    if secret_bytes.len() != ENTROPY_BYTES {
        return Err(Error::RecoveredSecretInvalid);
    }
    let secret = BigInt::from_bytes_be(Sign::Plus, &secret_bytes);
    let prime = prime();
    if secret >= prime {
        return Err(Error::SecretOutsideField);
    }

    let group_id = random_group_id();
    let language = mnemonic.language();
    let shares = Sss {
        threshold: config.threshold,
        share_amount: config.share_count,
        prime,
    }
    .split(secret);

    shares
        .into_iter()
        .map(|(index, value)| {
            let entropy = bigint_to_fixed_entropy(value)?;
            let mnemonic = Mnemonic::from_entropy_in(language, &entropy)
                .map_err(|_| Error::RecoveredSecretInvalid)?;
            Ok(Share {
                group_id,
                threshold: config.threshold,
                share_count: config.share_count,
                index,
                language,
                mnemonic,
            })
        })
        .collect()
}

/// Recovers a mnemonic from exactly the threshold number of shares.
pub fn combine(shares: &[Share]) -> Result<Mnemonic, Error> {
    let first = shares.first().ok_or(Error::InvalidShareFormat)?;
    if shares.len() != first.threshold {
        return Err(Error::WrongShareCount {
            expected: first.threshold,
            actual: shares.len(),
        });
    }
    if shares.iter().any(|share| {
        share.group_id != first.group_id
            || share.threshold != first.threshold
            || share.share_count != first.share_count
            || share.language != first.language
    }) {
        return Err(Error::MixedShareSets);
    }
    let mut indices = shares.iter().map(|share| share.index).collect::<Vec<_>>();
    indices.sort_unstable();
    if indices.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::DuplicateShareIndex);
    }

    let values = shares
        .iter()
        .map(|share| {
            (
                share.index,
                BigInt::from_bytes_be(Sign::Plus, &share.mnemonic.to_entropy()),
            )
        })
        .collect::<Vec<_>>();
    let recovered = Sss {
        threshold: first.threshold,
        share_amount: first.share_count,
        prime: prime(),
    }
    .recover(&values);
    let entropy = bigint_to_fixed_entropy(recovered)?;
    Mnemonic::from_entropy_in(first.language, &entropy).map_err(|_| Error::RecoveredSecretInvalid)
}

fn validate_config(config: SplitConfig) -> Result<(), Error> {
    if config.threshold < 2
        || config.threshold >= config.share_count
        || config.share_count > MAX_SHARES
    {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

fn prime() -> BigInt {
    BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("constant is a valid prime")
}

fn bigint_to_fixed_entropy(value: BigInt) -> Result<[u8; ENTROPY_BYTES], Error> {
    let (_, bytes) = value.to_bytes_be();
    if bytes.len() > ENTROPY_BYTES {
        return Err(Error::RecoveredSecretInvalid);
    }
    let mut entropy = [0; ENTROPY_BYTES];
    entropy[ENTROPY_BYTES - bytes.len()..].copy_from_slice(&bytes);
    Ok(entropy)
}

fn random_group_id() -> [u8; 16] {
    use rand::{rngs::OsRng, RngCore};

    let mut group_id = [0; 16];
    OsRng.fill_bytes(&mut group_id);
    group_id
}

fn parse_usize(value: Option<&str>) -> Result<usize, Error> {
    value
        .ok_or(Error::InvalidShareFormat)?
        .parse()
        .map_err(|_| Error::InvalidShareFormat)
}

fn language_code(language: Language) -> &'static str {
    match language {
        Language::English => "en",
        Language::SimplifiedChinese => "zh-hans",
        Language::TraditionalChinese => "zh-hant",
        Language::Czech => "cs",
        Language::French => "fr",
        Language::Italian => "it",
        Language::Japanese => "ja",
        Language::Korean => "ko",
        Language::Portuguese => "pt",
        Language::Spanish => "es",
    }
}

fn parse_language(code: &str) -> Result<Language, Error> {
    match code {
        "en" => Ok(Language::English),
        "zh-hans" => Ok(Language::SimplifiedChinese),
        "zh-hant" => Ok(Language::TraditionalChinese),
        "cs" => Ok(Language::Czech),
        "fr" => Ok(Language::French),
        "it" => Ok(Language::Italian),
        "ja" => Ok(Language::Japanese),
        "ko" => Ok(Language::Korean),
        "pt" => Ok(Language::Portuguese),
        "es" => Ok(Language::Spanish),
        _ => Err(Error::InvalidShareFormat),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_group_id(value: &str) -> Result<[u8; 16], Error> {
    if value.len() != 32 {
        return Err(Error::InvalidShareFormat);
    }
    let mut group_id = [0; 16];
    for (index, byte) in group_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Error::InvalidShareFormat)?;
    }
    Ok(group_id)
}

fn share_checksum(share: &Share) -> u32 {
    let value = format!(
        "shamir39-v1:{}:{}:{}:{}:{}:{}",
        hex_encode(&share.group_id),
        share.threshold,
        share.share_count,
        share.index,
        language_code(share.language),
        share.mnemonic,
    );
    crc32fast::hash(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mnemonic() -> Mnemonic {
        Mnemonic::from_entropy_in(Language::English, &[0; ENTROPY_BYTES]).unwrap()
    }

    fn config() -> SplitConfig {
        SplitConfig {
            threshold: 3,
            share_count: 5,
        }
    }

    #[test]
    fn split_and_combine_preserves_leading_zero_entropy() {
        let original = mnemonic();
        let shares = split(&original, config()).unwrap();
        assert_eq!(combine(&shares[..3]).unwrap(), original);
    }

    #[test]
    fn shares_round_trip_through_text() {
        let shares = split(&mnemonic(), config()).unwrap();
        let parsed = shares
            .iter()
            .map(|share| share.to_string().parse::<Share>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(combine(&parsed[..3]).unwrap(), mnemonic());
    }

    #[test]
    fn combine_rejects_mixed_share_sets() {
        let first = split(&mnemonic(), config()).unwrap();
        let second = split(&mnemonic(), config()).unwrap();
        assert_eq!(
            combine(&[first[0].clone(), first[1].clone(), second[2].clone()]),
            Err(Error::MixedShareSets)
        );
    }

    #[test]
    fn combine_rejects_duplicate_and_insufficient_shares() {
        let shares = split(&mnemonic(), config()).unwrap();
        assert_eq!(
            combine(&shares[..2]),
            Err(Error::WrongShareCount {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            combine(&[shares[0].clone(), shares[0].clone(), shares[2].clone()]),
            Err(Error::DuplicateShareIndex)
        );
    }

    #[test]
    fn parse_rejects_invalid_metadata() {
        assert!("shamir39-v1:not-a-group:3:5:1:en:00000000:abandon"
            .parse::<Share>()
            .is_err());
    }

    #[test]
    fn parse_rejects_tampered_metadata() {
        let share = split(&mnemonic(), config()).unwrap().remove(0);
        let tampered = share.to_string().replacen(":3:5:", ":4:5:", 1);
        assert_eq!(tampered.parse::<Share>(), Err(Error::InvalidShareFormat));
    }

    #[test]
    fn config_rejects_unsafe_or_unrepresentable_values() {
        assert_eq!(
            split(
                &mnemonic(),
                SplitConfig {
                    threshold: 1,
                    share_count: 2
                }
            ),
            Err(Error::InvalidConfig)
        );
        assert_eq!(
            split(
                &mnemonic(),
                SplitConfig {
                    threshold: 3,
                    share_count: 3
                }
            ),
            Err(Error::InvalidConfig)
        );
        assert_eq!(
            split(
                &mnemonic(),
                SplitConfig {
                    threshold: 3,
                    share_count: 2049
                }
            ),
            Err(Error::InvalidConfig)
        );
    }
}
