use bip39::{Mnemonic, Language};
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;
use rand::{thread_rng, RngCore};

const PRIME_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

fn generate_secure_entropy(byte_length: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; byte_length];
    thread_rng().fill_bytes(&mut entropy);
    entropy
}
fn bytes_to_mnemonic(bytes: &[u8], language: Language) -> Mnemonic {
    Mnemonic::from_entropy_in(language, bytes).expect("Valid entropy")
}

fn generate_shares(mnemonic: &Mnemonic) -> Vec<Mnemonic> {
    let secret_bytes = mnemonic.to_entropy();
    let secret = BigInt::from_bytes_be(num_bigint::Sign::Plus, &secret_bytes);

    let sss = SSS {
        threshold: 3,
        share_amount: 5,
        prime: BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("Valid prime"),
    };

    let shares = sss.split(secret);

    shares.into_iter().map(|share| {
        let share_bytes = share.1.to_bytes_be().1;
        bytes_to_mnemonic(&share_bytes, Language::SimplifiedChinese)
    }).collect()
}

fn reconstruct_secret(shares: &[Mnemonic]) -> Mnemonic {
    let sss = SSS {
        threshold: 3,
        share_amount: 5,
        prime: BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("Valid prime"),
    };

    let bigint_shares = shares.iter().map(|share| {
        let bytes = share.to_entropy();
        println!("Share's entropy: {:?}", bytes);
        (5, BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes))
    }).collect::<Vec<(usize, BigInt)>>();

    let reconstructed_secret = sss.recover(&bigint_shares);
    let secret_bytes = reconstructed_secret.to_bytes_be().1;
    println!("Reconstructed entropy: {:?}", secret_bytes);
    bytes_to_mnemonic(&secret_bytes, Language::SimplifiedChinese)
}

fn main() {
    let entropy = generate_secure_entropy(32);
    println!("{:?}", entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::SimplifiedChinese, &entropy).expect("valid entropy");
    println!("Original mnemonic: {}", mnemonic);

    let shares = generate_shares(&mnemonic);
    println!("Generated shares:");
    for (i, share) in shares.iter().enumerate() {
        println!("Share {}: {}", i + 1, share);
    }

    // Reconstruct secret using any 3 shares
    let reconstructed = reconstruct_secret(&shares[0..3]);
    println!("Reconstructed mnemonic: {}", reconstructed);

    assert_eq!(mnemonic, reconstructed, "Reconstruction failed");
}
