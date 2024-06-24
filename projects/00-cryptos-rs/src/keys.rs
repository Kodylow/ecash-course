use std::ops::{Mul, Rem};

use bitcoin_num::uint::Uint256;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::curves::{mod_pow, pow, Curve, Generator, Point, INF};
use crate::ripemd160::ripemd160;

// Secret key generation
pub fn gen_secret_key(n: &Uint256) -> Uint256 {
    loop {
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes);
        let key = Uint256::from_be_bytes(key_bytes);
        if key >= Uint256::from_u64(1).unwrap() && key < *n {
            return key;
        }
    }
}

impl Mul<&Point> for Uint256 {
    type Output = Point;

    fn mul(self, point: &Point) -> Point {
        point.clone() * self
    }
}

// Public key - specific functions, esp encoding / decoding
pub struct PublicKey(pub Point);

impl PublicKey {
    pub fn from_point(pt: Point) -> Self {
        PublicKey(pt)
    }

    pub fn from_sk(sk: &Uint256, gen: &Generator) -> Self {
        let pk = sk.clone() * &gen.G;
        PublicKey::from_point(pk)
    }

    pub fn from_bytes(b: &[u8], curve: &Curve) -> PublicKey {
        PublicKey::from_point(PublicKey::decode(b, curve))
    }

    pub fn decode(b: &[u8], curve: &Curve) -> Point {
        assert!(b.len() == 33 || b.len() == 65);

        if b[0] == 4 {
            let x = Uint256::from_be_bytes(b[1..33].try_into().unwrap());
            let y = Uint256::from_be_bytes(b[33..65].try_into().unwrap());
            return Point {
                curve: curve.clone(),
                x: Some(x),
                y: Some(y),
            };
        }

        assert!(b[0] == 2 || b[0] == 3);
        let is_even = b[0] == 2;
        let x = Uint256::from_be_bytes(b[1..33].try_into().unwrap());

        let p = &curve.p;
        let y2 = (pow(&x, 3) + Uint256::from_u64(7).unwrap()) % *p;
        let mut y = mod_pow(&y2, &((*p + Uint256::from_u64(1).unwrap()) >> 2), p);
        if (y % Uint256::from_u64(2).unwrap() == Uint256::from_u64(0).unwrap()) != is_even {
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
            let prefix = if self
                .0
                .y
                .as_ref()
                .unwrap()
                .rem(Uint256::from_u64(2).unwrap())
                == Uint256::from_u64(0).unwrap()
            {
                2u8
            } else {
                3u8
            };
            let mut res = vec![prefix];
            let x_bytes = self.0.x.as_ref().unwrap().to_bytes();
            let x_bytes_u8: &[u8] = bytemuck::cast_slice(&x_bytes);
            res.extend_from_slice(x_bytes_u8);
            res
        } else {
            let mut res = vec![4u8];
            let x_bytes = self.0.x.as_ref().unwrap().to_bytes();
            let x_bytes_u8: &[u8] = bytemuck::cast_slice(&x_bytes);
            res.extend_from_slice(x_bytes_u8);
            let y_bytes = self.0.y.as_ref().unwrap().to_bytes();
            let y_bytes_u8: &[u8] = bytemuck::cast_slice(&y_bytes);
            res.extend_from_slice(y_bytes_u8);
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
pub fn gen_key_pair(gen: &Generator) -> (Uint256, PublicKey) {
    let sk = gen_secret_key(&gen.n);
    let pk = PublicKey::from_sk(&sk, gen);
    (sk, pk)
}

// Base58 encoding / decoding utilities
const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58encode(b: &[u8]) -> String {
    let mut n = Uint256::from_be_bytes(b.try_into().expect("slice with incorrect length"));
    let mut chars = Vec::new();
    while n > Uint256::from_u64(0).unwrap() {
        let quotient = n / Uint256::from_u64(58).unwrap();
        let remainder = n % Uint256::from_u64(58).unwrap();
        chars.push(
            ALPHABET
                .chars()
                .nth(remainder.low_u64() as usize) // Use low_u64() instead of to_u64()
                .unwrap(),
        );
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
    let mut n = Uint256::from_u64(0).unwrap();
    for c in res.chars() {
        n = n * Uint256::from_u64(58).unwrap()
            + Uint256::from_u64(ALPHABET.find(c).unwrap() as u64).unwrap();
    }
    let bytes = n.to_bytes();
    let mut byte_vec = Vec::new();
    for &num in &bytes {
        byte_vec.extend_from_slice(&num.to_be_bytes());
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
