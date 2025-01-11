# Shamir39-rs

[![CI](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/Ev3rlasting/shamir39-rs/actions/workflows/ci.yml)

This project is a Rust implementation of [Shamir's Secret Sharing scheme](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) combined with BIP-39 mnemonics. It allows you to split a secret into multiple shares and reconstruct it using a subset of those shares.

## Warning

⚠️ **This is an experimental project. No security audit or review has been conducted. Use with caution in production environments. Future updates may introduce breaking changes.** ⚠️ 

## Features
- Generate a new mnemonic and split it into shares.
- Set your own m-out-of-n rules.
- Apply Shamir's Secret Sharing (SSS) on an existing mnemonic.
- Reconstruct a mnemonic from provided SSS shares.
- Supports multiple languages under BIP-39 standards.

## Prerequisites
- Rust and Cargo installed on your system.

## Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/Ev3rlasting/shamir39-rs
   cd shamir39-rs
   ```
2. Build the project:
   ```bash
   cargo build
   ```

## Usage
Run the program using Cargo:
```bash
cargo run
```

Follow the on-screen instructions to select a language, generate mnemonics, apply SSS, or reconstruct mnemonics.

## Example

Here's an example of generating a new mnemonic and splitting it into shares:

```
Select Language
1. English
2. Simplified Chinese
3. Traditional Chinese
4. Czech
5. French
6. Italian
7. Japanese
8. Korean
9. Portuguese
10. Spanish
Enter the number corresponding to your choice (default is English): Choose an option:

1. Generate a new mnemonic
2. Apply SSS on an existing mnemonic
3. Reconstruct mnemonic by providing SSS shares
Enter the number corresponding to your choice: Enter the threshold (n) for SSS (default is 3): Enter the total number of shares (m) for SSS (default is 5):
 
Original mnemonic: order box diamond wish slush spin doll history never there fuel bronze mango sound beef near marriage debris coffee brush analyst call ill unusual

Generated shares:
Share 1: ability giant uncle weather object blame enhance indoor sadness punch together grant ivory wrap traffic because only parrot powder vibrant swift raise salute twin link
Share 2: able sing grab surround easily letter pair feed pyramid same siege drift rapid suit invite hold share mirror drive parent screen suffer pole aerobic anger
Share 3: about spot lucky tissue aim ancient soon tortoise display silent miracle vocal soap blossom laundry bunker ball exhibit allow crew solar modify surge ski nest
Share 4: above layer enlist bacon strike quality swear cereal hunt ski cross large size roast work circle license town veteran provide across spy first dignity book
Share 5: absent slight resist green roast inner seminar below dirt settle roof surprise plunge season volcano minimum basket fall animal art front nose burger exit hour
Reconstructed mnemonic: order box diamond wish slush spin doll history never there fuel bronze mango sound beef near marriage debris coffee brush analyst call ill unusual, please verify
```

Here's an example of reconstructing a mnemonic using Simplified Chinese:

```
Select Language
1. English
2. Simplified Chinese
3. Traditional Chinese
4. Czech
5. French
6. Italian
7. Japanese
8. Korean
9. Portuguese
10. Spanish
Enter the number corresponding to your choice (default is English): 2
Choose an option:
1. Generate a new mnemonic
2. Apply SSS on an existing mnemonic
3. Reconstruct mnemonic by providing SSS shares
Enter the number corresponding to your choice: 3
Enter the number of shares you will provide: 3
Enter share 1: 了 滩 绿 顿 足 月 着 的 扬 午 景 典 罪 陪 架 义 盾 司 已 它 海 紧 谋 眉 渠
Enter share 2: 在 强 参 顿 怕 量 份 掩 珍 溶 株 续 轴 排 司 降 恐 忙 税 恩 支 刺 纠 巨 警
Enter share 3: 一 望 斑 研 某 活 摇 离 维 酷 吉 钻 抬 士 味 仗 已 树 元 碳 问 盾 恢 怀 株

Reconstructed mnemonic: 密 勇 诉 灌 高 日 瓦 从 纠 纹 方 喝 言 七 推 愿 患 黎 浇 又 五 仓 甘 线
```

## Testing
Run the tests using Cargo:
```bash
cargo test
```

## License
MIT

