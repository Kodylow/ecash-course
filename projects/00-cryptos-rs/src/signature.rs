use std::io::{Cursor, Read};
use std::ops::Mul;

use primitive_types::U256;

use crate::bitcoin::BITCOIN;
use crate::curves::inv;
use crate::keys::{gen_secret_key, PublicKey};
use crate::sha256::hash256;

// ECDSA Signature
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r: U256,
    pub s: U256,
}

impl Signature {
    pub fn decode(der: &[u8]) -> Self {
        let mut s = Cursor::new(der);
        let mut byte = [0u8; 1];
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x30);
        s.read_exact(&mut byte).unwrap();
        let length = byte[0];
        assert_eq!(length as usize, der.len() - 2);
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x02);
        s.read_exact(&mut byte).unwrap();
        let rlength = byte[0];
        let mut r = vec![0; rlength as usize];
        s.read_exact(&mut r).unwrap();
        let r = U256::from_big_endian(&r);
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x02);
        s.read_exact(&mut byte).unwrap();
        let slength = byte[0];
        let mut s_vec = vec![0; slength as usize];
        s.read_exact(&mut s_vec).unwrap();
        let s = U256::from_big_endian(&s_vec);
        assert_eq!(der.len(), 6 + rlength as usize + slength as usize);
        Signature { r, s }
    }

    pub fn encode(&self) -> Vec<u8> {
        fn dern(n: &U256) -> Vec<u8> {
            let mut nb = vec![0u8; 32];
            n.to_big_endian(&mut nb);
            if nb[0] >= 0x80 {
                nb.insert(0, 0x00);
            }
            nb
        }

        let rb = dern(&self.r);
        let sb = dern(&self.s);
        let mut content = vec![0x02, rb.len() as u8];
        content.extend(rb);
        content.push(0x02);
        content.push(sb.len() as u8);
        content.extend(sb);
        let mut frame = vec![0x30, content.len() as u8];
        frame.extend(content);
        frame
    }
}

pub fn sign_ecdsa(secret_key: &U256, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let z = U256::from_big_endian(&hash256(message.to_vec()));

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let P = PublicKey::from_sk(&k, &BITCOIN.gen);

    let r = P.0.x.clone().unwrap();
    let s = (inv(k, *n) * (z + *secret_key * r)) % *n;

    // Print values for debugging
    println!("r: {}", r);
    println!("s before adjustment: {}", s);
    println!("n: {}", n);

    let s = if s > *n / U256::from(2) { *n - s } else { s };

    // Print adjusted s
    println!("s after adjustment: {}", s);

    let s = (s + *n) % *n; // Ensure s is positive

    // Print final s
    println!("s final: {}", s);

    Signature { r, s }
}

pub fn verify_ecdsa(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= U256::from(1) && sig.r < *n);
    assert!(sig.s >= U256::from(1) && sig.s < *n);

    let z = U256::from_big_endian(&hash256(message.to_vec()));

    let w = inv(sig.s, *n);
    let u1 = (z * w) % *n;
    let u2 = (sig.r * w) % *n;
    #[allow(non_snake_case)]
    let pubkey_point = &public_key.0;
    #[allow(non_snake_case)]
    let P = BITCOIN.gen.G.clone().mul(u1) + pubkey_point.clone().mul(u2);
    P.x.unwrap() == sig.r
}

pub fn sign_schnorr(secret_key: &U256, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let R = PublicKey::from_sk(&k, &BITCOIN.gen);

    let r = R.0.x.clone().unwrap();
    let mut bytes_vec = vec![0u8; 32];
    r.to_big_endian(&mut bytes_vec);
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = U256::from_big_endian(&hashed);
    let s = (k + e * *secret_key) % *n;

    Signature { r, s }
}

pub fn verify_schnorr(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= U256::from(1) && sig.r < *n);
    assert!(sig.s >= U256::from(1) && sig.s < *n);

    let mut bytes_vec = vec![0u8; 32];
    sig.r.to_big_endian(&mut bytes_vec);
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = U256::from_big_endian(&hashed);
    #[allow(non_snake_case)]
    let pubkey_point = &public_key.0;
    #[allow(non_snake_case)]
    let R = BITCOIN.gen.G.clone().mul(sig.s.clone()) + (-pubkey_point.clone().mul(e));

    R.x.unwrap() == sig.r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_encode_decode() {
        let r = U256::from(12345);
        let s = U256::from(67890);
        let sig = Signature { r, s };
        let der = sig.encode();
        let decoded_sig = Signature::decode(&der);
        assert_eq!(sig, decoded_sig);
    }

    #[test]
    fn test_signature_der_encoding() {
        let r = U256::from_dec_str(
            "4051293998585674784991639592782214972820158391371785981004352359465450369227",
        )
        .unwrap();
        let s = U256::from_dec_str(
            "14135989968836420515709829771811628865775953163796562851092287839230222744152",
        )
        .unwrap();
        let sig = Signature { r, s };
        let der = sig.encode();
        let expected_der = hex::decode("3044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a58").unwrap();
        assert_eq!(der, expected_der);
    }

    #[test]
    fn test_sign_ecdsa() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let message = b"test message";

        println!("Secret Key: {}", secret_key);
        println!("Message: {:?}", message);

        let sig = sign_ecdsa(&secret_key, message);

        println!("Signature r: {}", sig.r);
        println!("Signature s: {}", sig.s);

        let public_key = PublicKey::from_sk(&secret_key, &BITCOIN.gen);

        println!("Public Key: {:?}", public_key);

        let verification_result = verify_ecdsa(&public_key, message, &sig);

        println!("Verification Result: {}", verification_result);

        assert!(verification_result);
    }

    #[test]
    fn test_verify_ecdsa() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let public_key = PublicKey::from_sk(&secret_key, &BITCOIN.gen);
        let message = b"test message";
        let sig = sign_ecdsa(&secret_key, message);
        assert!(verify_ecdsa(&public_key, message, &sig));
    }

    #[test]
    fn test_sign_schnorr() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let message = b"test message";
        let sig = sign_schnorr(&secret_key, message);
        assert!(verify_schnorr(
            &PublicKey::from_sk(&secret_key, &BITCOIN.gen),
            message,
            &sig
        ));
    }

    #[test]
    fn test_verify_schnorr() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let public_key = PublicKey::from_sk(&secret_key, &BITCOIN.gen);
        let message = b"test message";
        let sig = sign_schnorr(&secret_key, message);
        assert!(verify_schnorr(&public_key, message, &sig));
    }
}
