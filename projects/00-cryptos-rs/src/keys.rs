use std::ops::Mul;

use num_bigint::BigUint;
use num_traits::{Euclid, One, ToPrimitive, Zero};
use rand::Rng;

use crate::bitcoin::BITCOIN;
// Utilities to generate secret/public key pairs and Bitcoin address
// (note: using "secret" instead of "private" so that sk and pk are
// easy consistent shortcuts of the two without collision)
use crate::curves::Point;
use crate::ripemd160::ripemd160;
use crate::sha256::{hash256, sha256};

impl Mul<&Point> for &BigUint {
    type Output = Point;

    fn mul(self, rhs: &Point) -> Point {
        // Implement the multiplication logic here
        // This is a placeholder; replace with actual logic
        Point {
            curve: rhs.curve.clone(),
            x: rhs.x.clone(),
            y: rhs.y.clone(),
        }
    }
}

// Secret key generation
pub fn gen_secret_key(n: &BigUint) -> BigUint {
    loop {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        let key = BigUint::from_bytes_be(&key);
        if &BigUint::one() <= &key && &key < n {
            return key;
        }
    }
}

// Public key - specific functions, esp encoding / decoding
pub struct PublicKey {
    pub x: Option<BigUint>,
    pub y: Option<BigUint>,
}

impl PublicKey {
    pub fn from_point(pt: Point) -> Self {
        PublicKey { x: pt.x, y: pt.y }
    }

    pub fn to_point(&self) -> Point {
        Point {
            curve: BITCOIN.gen.G.curve.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }

    pub fn from_sk(sk: &BigUint) -> Self {
        let pk = sk * &BITCOIN.gen.G;
        PublicKey::from_point(pk)
    }

    pub fn decode(b: &[u8]) -> Self {
        assert!(b.len() == 33 || b.len() == 65);
        if b[0] == 4 {
            let x = BigUint::from_bytes_be(&b[1..33]);
            let y = BigUint::from_bytes_be(&b[33..65]);
            PublicKey {
                x: Some(x),
                y: Some(y),
            }
        } else {
            let is_even = b[0] == 2;
            let x = BigUint::from_bytes_be(&b[1..33]);
            let p = &BITCOIN.gen.G.curve.p;
            let y2 = (x.modpow(&BigUint::from(3u32), p) + BigUint::from(7u32)) % p;
            let y = y2.modpow(&((p + 1u32) / 4u32), p);
            let y = if (y.clone() % 2u32 == BigUint::zero()) == is_even {
                y
            } else {
                p - y
            };
            PublicKey {
                x: Some(x),
                y: Some(y),
            }
        }
    }

    pub fn encode(&self, compressed: bool, hash160: bool) -> Vec<u8> {
        let pkb = if compressed {
            let prefix = if self.y.as_ref().unwrap() % 2u32 == BigUint::zero() {
                2u8
            } else {
                3u8
            };
            let mut pkb = vec![prefix];
            pkb.extend(self.x.as_ref().unwrap().to_bytes_be());
            pkb
        } else {
            let mut pkb = vec![4u8];
            pkb.extend(self.x.as_ref().unwrap().to_bytes_be());
            pkb.extend(self.y.as_ref().unwrap().to_bytes_be());
            pkb
        };
        if hash160 {
            let sha256 = sha256(pkb);
            ripemd160(&sha256).to_vec()
        } else {
            pkb
        }
    }

    pub fn address(&self, net: &str, compressed: bool) -> String {
        let pkb_hash = self.encode(compressed, true);
        let version = match net {
            "main" => vec![0x00],
            "test" => vec![0x6f],
            _ => panic!("Unknown network"),
        };
        let mut ver_pkb_hash = version;
        ver_pkb_hash.extend(pkb_hash);
        let checksum = &hash256(ver_pkb_hash.clone())[..4];
        ver_pkb_hash.extend(checksum);
        b58encode(&ver_pkb_hash)
    }
}

// Convenience functions
pub fn gen_key_pair() -> (BigUint, PublicKey) {
    let sk = gen_secret_key(&BITCOIN.gen.n);
    let pk = PublicKey::from_sk(&sk);
    (sk, pk)
}

// Base58 encoding / decoding utilities
const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58encode(b: &[u8]) -> String {
    let mut n = BigUint::from_bytes_be(b);
    let mut chars = Vec::new();
    while n > BigUint::zero() {
        let (quotient, remainder) = n.div_rem_euclid(&BigUint::from(58u32));
        chars.push(ALPHABET.chars().nth(remainder.to_usize().unwrap()).unwrap());
        n = quotient;
    }
    let num_leading_zeros = b.iter().take_while(|&&x| x == 0).count();
    let mut res = String::new();
    for _ in 0..num_leading_zeros {
        res.push('1');
    }
    res.extend(chars.iter().rev());
    res
}

fn b58decode(res: &str) -> Vec<u8> {
    let mut n = BigUint::zero();
    for c in res.chars() {
        n = n * 58u32 + BigUint::from(ALPHABET.find(c).unwrap());
    }
    let mut bytes = n.to_bytes_be();
    let num_leading_zeros = res.chars().take_while(|&c| c == '1').count();
    for _ in 0..num_leading_zeros {
        bytes.insert(0, 0);
    }
    bytes
}

pub fn address_to_pkb_hash(b58check_address: &str) -> Vec<u8> {
    let byte_address = b58decode(b58check_address);
    assert_eq!(
        hash256(byte_address[..21].to_vec())[..4].to_vec(),
        byte_address[21..].to_vec()
    );
    byte_address[1..21].to_vec()
}

#[test]
fn test_public_key_gen() {
    // Example taken from Chapter 4 of Mastering Bitcoin
    let sk = BigUint::from_bytes_be(
        &hex::decode("1E99423A4ED27608A15A2616A2B0E9E52CED330AC530EDCC32C8FFC6A526AEDD").unwrap(),
    );
    let public_key = PublicKey::from_sk(&sk);
    assert_eq!(
        format!("{:064x}", public_key.x.unwrap()).to_uppercase(),
        "F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A"
    );
    assert_eq!(
        format!("{:064x}", public_key.y.unwrap()).to_uppercase(),
        "07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB"
    );
}

#[test]
fn test_btc_addresses() {
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
            "000000000000000000000000000000000000000000000000000000000012345deadbeef",
            "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1",
        ),
        (
            "test",
            true,
            "0000000000000000000000000000000000000000000000000000000000000000000002020",
            "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH",
        ),
        (
            "test",
            false,
            "0000000000000000000000000000000000000000000000000000000000000000000005002",
            "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA",
        ),
    ];

    for (net, compressed, secret_key, expected_address) in tests {
        let sk = BigUint::from_bytes_be(&hex::decode(secret_key).unwrap());
        let pk = PublicKey::from_sk(&sk);
        let addr = pk.address(net, compressed);
        assert_eq!(addr, expected_address);

        let pkb_hash = pk.encode(compressed, true);
        let pkb_hash2 = address_to_pkb_hash(expected_address);
        assert_eq!(pkb_hash, pkb_hash2);
    }
}

#[test]
#[allow(non_snake_case)]
fn test_pk_sec() {
    use num_traits::FromPrimitive;
    let G = &BITCOIN.gen.G;

    let tests = vec![
        (&BigUint::from_u64(5000).unwrap() * G, false, "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10"),
        (&BigUint::from_u64(2018).unwrap().pow(5) * G, false, "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06"),
        (&BigUint::from_bytes_be(&hex::decode("deadbeef12345").unwrap()) * G, false, "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121"),
        (&BigUint::from_u64(5001).unwrap() * G, true, "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1"),
        (&BigUint::from_u64(2019).unwrap().pow(5) * G, true, "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701"),
        (&BigUint::from_bytes_be(&hex::decode("deadbeef54321").unwrap()) * G, true, "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690"),
    ];

    for (P, compressed, sec_gt) in tests {
        let sec = PublicKey::from_point(P.clone()).encode(compressed, false);
        assert_eq!(hex::encode(sec), sec_gt);

        let P2 = PublicKey::decode(&hex::decode(sec_gt).unwrap());
        assert_eq!(P.x, P2.x);
        assert_eq!(P.y, P2.y);
    }
}
