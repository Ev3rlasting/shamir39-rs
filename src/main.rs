use std::{
    io::{self, Write},
    str::FromStr,
};

use bip39::{Language, Mnemonic};
use rand::{rngs::OsRng, RngCore};
use shamir39_rs::{combine, split, Share, SplitConfig};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let language = prompt_language("Select share language")?;
    println!("Choose an option:");
    println!("1. Generate a new 24-word mnemonic and split it");
    println!("2. Split an existing 24-word mnemonic");
    println!("3. Recover a mnemonic from shares");
    println!("4. Convert a mnemonic to a target language");

    match prompt_usize("Choose an option")? {
        1 => {
            let mnemonic = generate_mnemonic(language)?;
            println!("Original mnemonic: {mnemonic}");
            print_shares(&mnemonic)?;
        }
        2 => {
            let mnemonic = prompt_mnemonic(language)?;
            print_shares(&mnemonic)?;
        }
        3 => recover_mnemonic()?,
        4 => {
            let source_language = prompt_language("Select source mnemonic language")?;
            let mnemonic = prompt_mnemonic(source_language)?;
            println!(
                "Converted mnemonic: {}",
                Mnemonic::from_entropy_in(language, &mnemonic.to_entropy())?
            );
        }
        _ => return Err("invalid option".into()),
    }
    Ok(())
}

fn print_shares(mnemonic: &Mnemonic) -> Result<(), Box<dyn std::error::Error>> {
    let threshold = prompt_usize("Recovery threshold")?;
    let share_count = prompt_usize("Total number of shares")?;
    let shares = split(
        mnemonic,
        SplitConfig {
            threshold,
            share_count,
        },
    )?;
    println!("Generated shares (keep the full line for each share):");
    for share in shares {
        println!("{share}");
    }
    Ok(())
}

fn recover_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
    let count = prompt_usize("Number of shares to provide")?;
    let mut shares = Vec::with_capacity(count);
    for index in 1..=count {
        let value = rpassword::prompt_password(format!("Share {index}: "))?;
        shares.push(Share::from_str(&value)?);
    }
    println!("Recovered mnemonic: {}", combine(&shares)?);
    Ok(())
}

fn prompt_mnemonic(language: Language) -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let value = rpassword::prompt_password("Mnemonic: ")?;
    Ok(Mnemonic::parse_in(language, value.trim())?)
}

fn generate_mnemonic(language: Language) -> Result<Mnemonic, Box<dyn std::error::Error>> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut entropy[..]);
    Ok(Mnemonic::from_entropy_in(language, &entropy[..])?)
}

fn prompt_language(prompt: &str) -> Result<Language, Box<dyn std::error::Error>> {
    println!("{prompt}:");
    for (index, name) in language_names().iter().enumerate() {
        println!("{}. {name}", index + 1);
    }
    match prompt_usize("Language number")? {
        1 => Ok(Language::English),
        2 => Ok(Language::SimplifiedChinese),
        3 => Ok(Language::TraditionalChinese),
        4 => Ok(Language::Czech),
        5 => Ok(Language::French),
        6 => Ok(Language::Italian),
        7 => Ok(Language::Japanese),
        8 => Ok(Language::Korean),
        9 => Ok(Language::Portuguese),
        10 => Ok(Language::Spanish),
        _ => Err("invalid language number".into()),
    }
}

fn language_names() -> [&'static str; 10] {
    [
        "English",
        "Simplified Chinese",
        "Traditional Chinese",
        "Czech",
        "French",
        "Italian",
        "Japanese",
        "Korean",
        "Portuguese",
        "Spanish",
    ]
}

fn prompt_usize(prompt: &str) -> Result<usize, Box<dyn std::error::Error>> {
    print!("{prompt}: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().parse()?)
}
