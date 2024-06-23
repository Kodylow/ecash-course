# Ecash Development on Bitcoin - A Comprehensive Course

This is a course on how to build ecash applications on Bitcoin and contribute to upstream projects as an open source developer, specifically Fedimint, Cashu, and the ecosystem of Rust Bitcoin projects. The course assumes you've taken the first 2 Base58 courses on Bitcoin Transactions and Digital Signatures, and has optional sections covering the basics of each of the tools used in this course including the Rust programming language, the Nostr Protocol, Nix Development environments, and Git tooling options for open source contributions.

By the end of this course, you will be capable of starting or productively contributing to an open source Ecash Project in the Bitcoin Ecosystem.

## Curriculum

### Secion 0 (Optional): Nix & Git for Open Source Bitcoin Development

- Open Source Bitcoin Development
- The Nix Language
- Nix Package Management
- Nix Flakes for Developer Environments
- Git and How to Use It
- Flakebox: Rust Development with Nix
- Kody's Developer Environment

### Section 1 (Optional): Rust Programming

- Why Rust?
- Resources for Learning Rust
- Async Programming with Tokio
- Project 0: Rewriting an Elliptic Curve Crypto package in Rust

### Section 2: Ecash Fundamentals

- What is Ecash?
- Ecash Projects on Bitcoin
- Blinded Signature Schemes
- Project 1: Blinded Schnorr Signatures
- Project 2: Blinded Diffie-Helmann Key Exchange

### Section 3: The Cashu Ecash Protocol

- What is Cashu?
- Cashu NUTs: Notation, Usage, and Terminology
- Project 3: Let's make a Cashu Mint with Cashu Dev Kit

### Section 4: Fedimint - A Federated Application Framework

- What is Fedimint?
- Federated Consensus
- Fedimint's Ecash Scheme
- Project 4: Threshold BLS Signatures
- Project 5: Building a Fedimint Lightning Address Server w/Blinded Registration
- Project 6: Backing our Cashu Mint with Fedimint Ecash
  - Payment Options: Lightning, Fedimint Ecash, Onchain

### Section 4: Ecash Application Development

- Project 7: Building a MultiMint Ecash Wallet
- Project 8: Building an Ecash Wallet Extension for the Browser

### Section 5: Nostr Dev with Ecash

- What is Nostr?
- NIPs: Nostr Implementation Possibilities
- Project 9: Adding NIP-05 Address Support to our Lightning Address Server
- Project 10: Adding Nostr Wallet Connect to our MultiMint Wallet
- Project 11: Ecash Pay for use Nostr Data Vending Machines

### Section 6: Fedimint Module Development

- The Fedimint Module System w/Eric Sirion
- The Fedimint Custom Module Starter Template
- Project 12: Building a Simplicity Smart Contract Fedimint Module w/Christian Lewe

### Section 7: Open Source Bitcoin Contributions

- Adding Fedimint & Cashu Ecash support to Alby
- Adding Ecash Payment Options to a Nostr Relay
- Swapping a BLS blind signature scheme for Cashu
