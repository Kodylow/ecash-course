use std::ops::{Mul, Rem};

use primitive_types::U256;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::curves::{Curve, Generator, Point};
use crate::ripemd160::ripemd160;

// Secret key generation
pub fn gen_secret_key(n: &U256) -> U256 {
    loop {
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes);
        let key = U256::from_big_endian(&key_bytes);
        if key >= U256::from(1) && key < *n {
            return key;
        }
    }
}

impl Mul<&Point> for U256 {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        point.clone() * self
    }
}

// Public key - specific functions, esp encoding / decoding
#[derive(Debug)]
pub struct PublicKey(pub Point);

impl PublicKey {
    pub fn from_point(pt: Point) -> Self {
        PublicKey(pt)
    }

    pub fn from_sk(sk: &U256, gen: &Generator) -> Self {
        let pk = *sk * &gen.G;

        PublicKey::from_point(pk)
    }

    pub fn from_bytes(b: &[u8], curve: &Curve) -> PublicKey {
        PublicKey::from_point(PublicKey::decode(b, curve))
    }

    pub fn decode(b: &[u8], curve: &Curve) -> Point {
        assert!(b.len() == 33 || b.len() == 65);

        if b[0] == 4 {
            let x = U256::from_big_endian(&b[1..33]);
            let y = U256::from_big_endian(&b[33..65]);
            return Point {
                curve: curve.clone(),
                x: Some(x),
                y: Some(y),
            };
        }

        assert!(b[0] == 2 || b[0] == 3);
        let is_even = b[0] == 2;
        let x = U256::from_big_endian(&b[1..33]);

        let p = &curve.p;
        let y2 = (x.pow(U256::from(3)) + U256::from(7)) % *p;
        let exponent = ((*p + U256::from(1)) >> 2).low_u32();
        let mut y = y2.pow(U256::from(exponent));
        if (y % U256::from(2) == U256::from(0)) != is_even {
            y = *p - y;
        }
        Point {
            curve: curve.clone(),
            x: Some(x),
            y: Some(y),
        }
    }

    pub fn encode(&self, compressed: bool, hash160: bool) -> Vec<u8> {
        let mut pkb = if compressed {
            let prefix = if self.0.y.as_ref().unwrap().rem(U256::from(2)) == U256::from(0) {
                2u8
            } else {
                3u8
            };
            let mut res = vec![prefix];
            let mut x_bytes = [0u8; 32];
            self.0.x.as_ref().unwrap().to_big_endian(&mut x_bytes);
            res.extend_from_slice(&x_bytes);
            res
        } else {
            let mut res = vec![4u8];
            let mut x_bytes = [0u8; 32];
            self.0.x.as_ref().unwrap().to_big_endian(&mut x_bytes);
            res.extend_from_slice(&x_bytes);
            let mut y_bytes = [0u8; 32];
            self.0.y.as_ref().unwrap().to_big_endian(&mut y_bytes);
            res.extend_from_slice(&y_bytes);
            res
        };

        if hash160 {
            let sha256_hash = Sha256::digest(&pkb);
            let ripemd160_hash = ripemd160(&sha256_hash);
            pkb = ripemd160_hash.to_vec();
        }

        pkb
    }

    pub fn address(&self, net: &str, compressed: bool) -> String {
        let pkb_hash = self.encode(compressed, true);
        let version = match net {
            "main" => 0x00,
            "test" => 0x6f,
            _ => panic!("Unknown network"),
        };
        let mut ver_pkb_hash = vec![version];
        ver_pkb_hash.extend_from_slice(&pkb_hash);
        let checksum = &Sha256::digest(&Sha256::digest(&ver_pkb_hash))[..4];
        ver_pkb_hash.extend_from_slice(checksum);
        b58encode(&ver_pkb_hash)
    }
}

// Convenience functions
pub fn gen_key_pair(gen: &Generator) -> (U256, PublicKey) {
    let sk = gen_secret_key(&gen.n);
    let pk = PublicKey::from_sk(&sk, gen);
    (sk, pk)
}

// Base58 encoding / decoding utilities
const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58encode(b: &[u8]) -> String {
    let mut n = U256::from_big_endian(b);
    let mut chars = Vec::new();
    while n > U256::from(0) {
        let quotient = n / U256::from(58);
        let remainder = n % U256::from(58);
        chars.push(ALPHABET.chars().nth(remainder.low_u32() as usize).unwrap());
        n = quotient;
    }
    let num_leading_zeros = b.iter().take_while(|&&x| x == 0).count();
    let mut res = String::new();
    for _ in 0..num_leading_zeros {
        res.push(ALPHABET.chars().nth(0).unwrap());
    }
    res.extend(chars.iter().rev());
    res
}

fn b58decode(res: &str) -> Vec<u8> {
    let mut n = U256::from(0);
    for c in res.chars() {
        n = n * U256::from(58) + U256::from(ALPHABET.find(c).unwrap() as u64);
    }
    let mut byte_vec = Vec::new();
    n.to_big_endian(&mut byte_vec);
    let mut new_byte_vec: Vec<u8> = Vec::new();
    for &num in &byte_vec {
        new_byte_vec.extend_from_slice(&num.to_be_bytes());
    }
    let num_leading_zeros = res
        .chars()
        .take_while(|&c| c == ALPHABET.chars().nth(0).unwrap())
        .count();
    let mut res = vec![0u8; num_leading_zeros];
    res.extend_from_slice(&byte_vec);
    res
}

pub fn address_to_pkb_hash(b58check_address: &str) -> Vec<u8> {
    let byte_address = b58decode(b58check_address);
    let checksum = &Sha256::digest(&Sha256::digest(&byte_address[..21]))[..4];
    assert_eq!(&byte_address[21..], checksum);
    byte_address[1..21].to_vec()
}

#[test]
fn test_public_key_gen() {
    use crate::bitcoin::BITCOIN;
    // Example taken from Chapter 4 of Mastering Bitcoin
    let sk_hex = "1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD";

    let sk_bytes = hex::decode(sk_hex).unwrap();

    let sk = U256::from_big_endian(&sk_bytes);

    let public_key = PublicKey::from_sk(&sk, &BITCOIN.gen);

    let pk_x = public_key.0.x.unwrap();
    let pk_y = public_key.0.y.unwrap();

    let pk_x_hex = format!("{:064x}", pk_x).to_uppercase();
    let pk_y_hex = format!("{:064x}", pk_y).to_uppercase();

    assert_eq!(
        pk_x_hex,
        "F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A"
    );
    assert_eq!(
        pk_y_hex,
        "07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB"
    );
}

#[test]
fn test_btc_addresses() {
    use crate::bitcoin::BITCOIN;
    // tuples of (net, compressed, secret key in hex, expected compressed bitcoin
    // address string in b58check)
    let tests = vec![
        (
            "main",
            true,
            "3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6",
            "14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3",
        ),
        (
            "main",
            true,
            "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725",
            "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs",
        ),
        (
            "main",
            true,
            "000000000000000000000000000000000000000000000000000000000012345d",
            "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1",
        ),
        (
            "test",
            true,
            "0000000000000000000000000000000000000000000000000000000000002020",
            "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH",
        ),
        (
            "test",
            false,
            "000000000000000000000000000000000000000000000000000000000000138a",
            "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA",
        ),
    ];

    // test address encoding into b58check
    for (net, compressed, secret_key, expected_address) in tests.iter() {
        let sk = U256::from_big_endian(&hex::decode(secret_key).unwrap());
        let pk = PublicKey::from_sk(&sk, &BITCOIN.gen);
        let addr = pk.address(net, *compressed);
        assert_eq!(addr, *expected_address);
    }

    // test public key hash decoding from b58check
    for (net, compressed, secret_key, address) in tests.iter() {
        let sk = U256::from_big_endian(&hex::decode(secret_key).unwrap());
        let pk = PublicKey::from_sk(&sk, &BITCOIN.gen);
        // get the hash160 by stripping version byte and checksum
        let pkb_hash = pk.encode(*compressed, true);
        // now extract from the address, address_to_pkb_hash
        let pkb_hash2 = address_to_pkb_hash(address);
        assert_eq!(pkb_hash, pkb_hash2);
    }
}

#[test]
#[allow(non_snake_case)]
fn test_pk_sec() {
    use crate::bitcoin::BITCOIN;
    let G = &BITCOIN.gen.G;

    // these examples are taken from Programming Bitcoin Chapter 4 exercises
    let tests = vec![
        (U256::from(5000) * G, false, "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10"),
        (U256::from(2018u64).pow(U256::from(5)) * G, false, "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06"),
        (U256::from(0xdeadbeef12345u64) * G, false, "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121"),
        (U256::from(5001) * G, true, "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1"),
        (U256::from(2019u64).pow(U256::from(5)) * G, true, "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701"),
        (U256::from(0xdeadbeef54321u64) * G, true, "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690"),
    ];

    for (P, compressed, sec_gt) in tests.iter() {
        // encode
        let sec = PublicKey::from_point(P.clone()).encode(*compressed, false);
        assert_eq!(hex::encode(sec), *sec_gt);
        // decode
        let P2 = PublicKey::decode(&hex::decode(sec_gt).unwrap(), &BITCOIN.gen.G.curve);
        assert_eq!(P.x, P2.x);
        assert_eq!(P.y, P2.y);
    }
}
