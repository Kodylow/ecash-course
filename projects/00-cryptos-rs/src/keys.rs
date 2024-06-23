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
