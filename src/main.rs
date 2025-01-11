use bip39::Mnemonic;
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;
use rand::{thread_rng, RngCore};
use std::io::{self, Write};

const PRIME_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

fn generate_secure_entropy(byte_length: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; byte_length];
    thread_rng().fill_bytes(&mut entropy);
    entropy
}
fn bytes_to_mnemonic(bytes: &[u8], language: bip39::Language) -> Mnemonic {
    Mnemonic::from_entropy_in(language, bytes).expect("Valid entropy")
}

fn generate_shares(mnemonic: &Mnemonic, threshold: usize, share_amount: usize) -> Vec<Mnemonic> {
    let secret_bytes = mnemonic.to_entropy();
    let secret = BigInt::from_bytes_be(num_bigint::Sign::Plus, &secret_bytes);

    let sss = SSS {
        threshold,
        share_amount,
        prime: BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("Valid prime"),
    };

    let shares = sss.split(secret);

    shares.into_iter().map(|share| {
        let share_bytes = share.1.to_bytes_be().1;
        bytes_to_mnemonic(&share_bytes, bip39::Language::SimplifiedChinese)
    }).collect()
}

fn reconstruct_secret(shares: &[Mnemonic], threshold: usize) -> Mnemonic {
    let sss = SSS {
        threshold,
        share_amount: 10, // you don't need to provide this
        prime: BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("Valid prime"),
    };

    let bigint_shares = shares.iter().enumerate().map(|(index, share)| {
        let bytes = share.to_entropy();
        println!("Share's entropy: {:?}", bytes);
        (index+1, BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes))
    }).collect::<Vec<(usize, BigInt)>>();

    let reconstructed_secret = sss.recover(&bigint_shares);
    println!("Reconstructed secret: {}", reconstructed_secret);
    let secret_bytes = reconstructed_secret.to_bytes_be().1;
    bytes_to_mnemonic(&secret_bytes, bip39::Language::SimplifiedChinese)
}

fn main() {
    println!("Select Language");
    println!("1. English");
    println!("2. Simplified Chinese");
    println!("3. Traditional Chinese");
    println!("4. Czech");
    println!("5. French");
    println!("6. Italian");
    println!("7. Japanese");
    println!("8. Korean");
    println!("9. Portuguese");
    println!("10. Spanish");
    print!("Enter the number corresponding to your choice (default is 1): ");
    io::stdout().flush().unwrap();

    let mut language_choice = String::new();
    io::stdin().read_line(&mut language_choice).unwrap();
    let language_choice: usize = language_choice.trim().parse().unwrap_or(1);

    let language = match language_choice {
        2 => bip39::Language::SimplifiedChinese,
        3 => bip39::Language::TraditionalChinese,
        4 => bip39::Language::Czech,
        5 => bip39::Language::French,
        6 => bip39::Language::Italian,
        7 => bip39::Language::Japanese,
        8 => bip39::Language::Korean,
        9 => bip39::Language::Portuguese,
        10 => bip39::Language::Spanish,
        _ => bip39::Language::English,
    };

    println!("Choose an option:");
    println!("1. Generate a new mnemonic");
    println!("2. Apply SSS on an existing mnemonic");
    println!("3. Reconstruct mnemonic by providing SSS shares");
    print!("Enter the number corresponding to your choice: ");
    io::stdout().flush().unwrap();

    let mut option_choice = String::new();
    io::stdin().read_line(&mut option_choice).unwrap();
    let option_choice: usize = option_choice.trim().parse().unwrap_or(1);

    match option_choice {
        1 => {
            print!("Enter the threshold (n) for SSS (default is 3): ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut threshold_input = String::new();
            io::stdin().read_line(&mut threshold_input).expect("Failed to read line");
            let threshold: usize = threshold_input.trim().parse().unwrap_or(3);

            print!("Enter the total number of shares (m) for SSS (default is 5): ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut share_amount_input = String::new();
            io::stdin().read_line(&mut share_amount_input).expect("Failed to read line");
            let share_amount: usize = share_amount_input.trim().parse().unwrap_or(5);

            let entropy = generate_secure_entropy(32);
            println!("{:?}", entropy);
            let mnemonic = Mnemonic::from_entropy_in(language, &entropy).expect("valid entropy");
            println!("Original mnemonic: {}", mnemonic);

            let shares = generate_shares(&mnemonic, threshold, share_amount);
            println!("Generated shares:");
            for (i, share) in shares.iter().enumerate() {
                println!("Share {}: {}", i + 1, share);
            }
            let reconstructed = reconstruct_secret(&shares[0..threshold], threshold);
            println!("Reconstructed mnemonic: {}, please verify", reconstructed);
            assert_eq!(mnemonic, reconstructed, "Reconstruction failed");
        }
        2 => {
            print!("Enter your existing mnemonic (split by space): ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut existing_mnemonic = String::new();
            io::stdin().read_line(&mut existing_mnemonic).expect("Failed to read line");
            let mnemonic = Mnemonic::parse(existing_mnemonic.trim()).expect("valid mnemonic");

            print!("Enter the threshold (n) for SSS (default is 3): ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut threshold_input = String::new();
            io::stdin().read_line(&mut threshold_input).expect("Failed to read line");
            let threshold: usize = threshold_input.trim().parse().unwrap_or(3);

            print!("Enter the total number of shares (m) for SSS (default is 5): ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut share_amount_input = String::new();
            io::stdin().read_line(&mut share_amount_input).expect("Failed to read line");
            let share_amount: usize = share_amount_input.trim().parse().unwrap_or(5);

            let shares = generate_shares(&mnemonic, threshold, share_amount);
            println!("Generated shares:");
            for (i, share) in shares.iter().enumerate() {
                println!("Share {}: {}", i + 1, share);
            }
            let reconstructed = reconstruct_secret(&shares[0..threshold], threshold);
            println!("Reconstructed mnemonic: {}", reconstructed);
            assert_eq!(mnemonic, reconstructed, "Reconstruction failed");
        }
        3 => {
            print!("Enter the number of shares you will provide: ");
            io::stdout().flush().expect("Failed to flush stdout");
            let mut num_shares_input = String::new();
            io::stdin().read_line(&mut num_shares_input).expect("Failed to read line");
            let num_shares: usize = num_shares_input.trim().parse().unwrap_or(3);

            let mut shares = Vec::new();
            for i in 0..num_shares {
                print!("Enter share {}: ", i + 1);
                io::stdout().flush().expect("Failed to flush stdout");
                let mut share_input = String::new();
                io::stdin().read_line(&mut share_input).expect("Failed to read line");
                let share = Mnemonic::parse(share_input.trim()).expect("valid mnemonic");
                shares.push(share);
            }

            let reconstructed = reconstruct_secret(&shares, num_shares);
            println!("Reconstructed mnemonic: {}", reconstructed);
        }
        _ => {
            println!("Invalid choice, defaulting to generating a new mnemonic.");
        }
    }
}
