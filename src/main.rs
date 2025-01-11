use bip39::Mnemonic;
use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;
use rand::{thread_rng, RngCore};
use std::{fmt::Display, io::{self, Write}};

const PRIME_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
#[derive(Clone)]
struct Shamir39Share {
    index: usize, // offset of the share in the original generated share set
    share: Mnemonic,
    language: bip39::Language,
}
    
impl Shamir39Share {
    fn new(index: usize, share: Mnemonic, language: bip39::Language) -> Self {
        Self { index, share, language }
    }
}

impl Display for Shamir39Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word_list = match self.language {
            bip39::Language::English => bip39::Language::English.word_list(),
            bip39::Language::SimplifiedChinese => bip39::Language::SimplifiedChinese.word_list(),
            bip39::Language::TraditionalChinese => bip39::Language::TraditionalChinese.word_list(),
            bip39::Language::Czech => bip39::Language::Czech.word_list(),
            bip39::Language::French => bip39::Language::French.word_list(),
            bip39::Language::Italian => bip39::Language::Italian.word_list(),
            bip39::Language::Japanese => bip39::Language::Japanese.word_list(),
            bip39::Language::Korean => bip39::Language::Korean.word_list(),
            bip39::Language::Portuguese => bip39::Language::Portuguese.word_list(),
            bip39::Language::Spanish => bip39::Language::Spanish.word_list(),
        };

        let index_word = word_list[self.index as usize];

        write!(f, "{} {}", index_word, self.share)
    }
}

fn generate_secure_entropy(byte_length: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; byte_length];
    thread_rng().fill_bytes(&mut entropy);
    entropy
}
fn bytes_to_mnemonic(bytes: &[u8], language: bip39::Language) -> Mnemonic {
    Mnemonic::from_entropy_in(language, bytes).expect("Valid entropy")
}

fn generate_shares(mnemonic: &Mnemonic, threshold: usize, share_amount: usize, language: bip39::Language) -> Vec<Shamir39Share> {
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
        Shamir39Share::new(share.0, bytes_to_mnemonic(&share_bytes, language), language)
    }).collect()
}

fn reconstruct_secret(shares: &[Shamir39Share], threshold: usize, language: bip39::Language) -> Mnemonic {
    let sss = SSS {
        threshold,
        share_amount: shares.len(),
        prime: BigInt::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("Valid prime"),
    };

    let bigint_shares = shares.iter().map(|share| {
        let bytes = share.share.to_entropy();
        (share.index, BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes))
    }).collect::<Vec<(usize, BigInt)>>();

    let reconstructed_secret = sss.recover(&bigint_shares);
    let secret_bytes = reconstructed_secret.to_bytes_be().1;
    bytes_to_mnemonic(&secret_bytes, language)
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
    print!("Enter the number corresponding to your choice (default is English): ");
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

            let shares = generate_shares(&mnemonic, threshold, share_amount, language);
            println!("Generated shares:");
            for (i, share) in shares.iter().enumerate() {
                println!("Share {}: {}", i + 1, share);
            }
            let reconstructed = reconstruct_secret(&shares[0..threshold], threshold, language);
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

            let shares = generate_shares(&mnemonic, threshold, share_amount, language);
            println!("Generated shares:");
            for (i, share) in shares.iter().enumerate() {
                println!("Share {}: {}", i + 1, share);
            }
            let reconstructed = reconstruct_secret(&shares[0..threshold], threshold, language);
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
                
                let words: Vec<&str> = share_input.trim().split_whitespace().collect();
                let indexed_word = words[0];
                let index = language.word_list().iter().position(|&w| w == indexed_word)
                    .expect("Invalid share. Only supports shares generated by this tool");
                
                let share = Mnemonic::parse(&words[1..].join(" ")).expect("valid mnemonic");
                shares.push(Shamir39Share::new(index, share, language));
            }

            let reconstructed = reconstruct_secret(&shares, num_shares, language);
            println!("Reconstructed mnemonic: {}", reconstructed);
        }
        _ => {
            println!("Invalid choice, defaulting to generating a new mnemonic.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Language;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    #[test]
    fn test_generate_and_reconstruct_shares_english() {
        let existing_mnemonic_str = "front gas news expect quantum indoor sound dad eyebrow screen shoulder safe hazard cabin modify soon grass drive reflect gospel thrive extra health ask";
        let existing_mnemonic = Mnemonic::parse(existing_mnemonic_str).expect("valid mnemonic");
        let threshold = 3;
        let share_amount = 6;
        let language = Language::English;
        let shares = generate_shares(&existing_mnemonic, threshold, share_amount, language);
        assert_eq!(shares.len(), share_amount);
        let mut indices: Vec<usize> = (0..share_amount).collect();
        indices.shuffle(&mut thread_rng());
        let selected_shares: Vec<Shamir39Share> = indices.iter().map(|&i| shares[i].clone()).collect();
        let reconstructed_mnemonic = reconstruct_secret(&selected_shares[0..threshold], threshold, language);
        assert_eq!(existing_mnemonic, reconstructed_mnemonic, "Reconstruction failed");
    }

    #[test]
    fn test_random_shares_reconstruction_chinese() {
        let existing_mnemonic_str = "密 勇 诉 灌 高 日 瓦 从 纠 纹 方 喝 言 七 推 愿 患 黎 浇 又 五 仓 甘 线";
        let existing_mnemonic = Mnemonic::parse(existing_mnemonic_str).expect("valid mnemonic");

        let threshold = 6;
        let share_amount = 20;
        let language = Language::SimplifiedChinese;

        let shares = generate_shares(&existing_mnemonic, threshold, share_amount, language);

        let mut indices: Vec<usize> = (0..share_amount).collect();
        indices.shuffle(&mut thread_rng());
        let selected_shares: Vec<Shamir39Share> = indices.iter().map(|&i| shares[i].clone()).collect();
        let reconstructed_mnemonic = reconstruct_secret(&selected_shares[0..threshold], threshold, language);
        assert_eq!(existing_mnemonic, reconstructed_mnemonic, "Reconstruction failed with random shares");
    }


}
