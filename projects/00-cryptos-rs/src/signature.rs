use std::io::{Cursor, Read};
use std::ops::Mul;

use crate::bitcoin::BITCOIN;
use crate::keys::{gen_secret_key, PublicKey};
use crate::ru256::RU256;
use crate::sha256::hash256;

// ECDSA Signature
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r: RU256,
    pub s: RU256,
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
        let r = RU256::from_bytes(&r);
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x02);
        s.read_exact(&mut byte).unwrap();
        let slength = byte[0];
        let mut s_vec = vec![0; slength as usize];
        s.read_exact(&mut s_vec).unwrap();
        let s = RU256::from_bytes(&s_vec);
        assert_eq!(der.len(), 6 + rlength as usize + slength as usize);
        Signature { r, s }
    }

    pub fn encode(&self) -> Vec<u8> {
        fn dern(n: &RU256) -> Vec<u8> {
            let mut nb = vec![0u8; 32];
            n.to_bytes(&mut nb);
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

pub fn sign_ecdsa(secret_key: &RU256, message: &[u8]) -> Signature {
    // Hash the message to sign
    let z = RU256::from_bytes(&hash256(message.to_vec()));

    // Generate a random nonce
    let k = gen_secret_key(&BITCOIN.gen.n);

    // Map the nonce scalar to a point on the SECP256k1 curve using the generator as
    // the base point
    #[allow(non_snake_case)]
    let R = PublicKey::from_sk(&k);

    // r is the x component of the point
    let r = R.0.x.clone();

    // Grab the group order
    let n = &BITCOIN.gen.n;

    // Compute s
    let s = (r.clone().mul_mod(secret_key, n).add_mod(&z, n)).div_mod(&k, n);

    Signature { r, s }
}

pub fn verify_ecdsa(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    // Hash the message
    let hash = RU256::from_bytes(&hash256(message.to_vec()));

    // Grab the group order
    let n = &BITCOIN.gen.n;

    // Calculate w = 1/s mod n
    let w = RU256::from_bytes(&[1]).div_mod(&sig.s, n);

    // Calculate u1 = hash * w mod n
    let u1 = hash.mul_mod(&w, n);

    // Calculate u2 = r * w mod n
    let u2 = sig.r.mul_mod(&w, n);

    // Calculate u1 * G
    let u1_point = BITCOIN.gen.G.clone().mul(u1);

    // Calculate u2 * public_key
    let u2_point = public_key.0.clone().mul(u2);

    // Calculate the verification point
    let verification_point = u1_point + u2_point;

    // Check if the x-coordinate of the verification point equals r
    verification_point.x == sig.r
}

pub fn sign_schnorr(secret_key: &RU256, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let R = PublicKey::from_sk(&k);

    let r = R.0.x.clone();
    let mut bytes_vec = vec![0u8; 32];
    r.to_bytes(&mut bytes_vec);
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = RU256::from_bytes(&hashed);
    let s = (k + e * secret_key.clone()) % n.clone();

    Signature { r, s }
}

pub fn verify_schnorr(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= RU256::from_u64(1) && sig.r < *n);
    assert!(sig.s >= RU256::from_u64(1) && sig.s < *n);

    let mut bytes_vec = vec![0u8; 32];
    sig.r.to_bytes(&mut bytes_vec);
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = RU256::from_bytes(&hashed);
    #[allow(non_snake_case)]
    let pubkey_point = &public_key.0;
    #[allow(non_snake_case)]
    let R = BITCOIN.gen.G.clone().mul(sig.s.clone()) + (-pubkey_point.clone().mul(e));

    R.x == sig.r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_encode_decode() {
        let r = RU256::from_u64(12345);
        let s = RU256::from_u64(67890);
        let sig = Signature { r, s };
        let der = sig.encode();
        let decoded_sig = Signature::decode(&der);
        assert_eq!(sig, decoded_sig);
    }

    #[test]
    fn test_signature_der_encoding() {
        let r = RU256::from_str_radix(
            "4051293998585674784991639592782214972820158391371785981004352359465450369227",
            10,
        )
        .unwrap();
        let s = RU256::from_str_radix(
            "14135989968836420515709829771811628865775953163796562851092287839230222744152",
            10,
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

        println!("Secret Key: {:?}", secret_key);
        println!("Message: {:?}", message);

        let sig = sign_ecdsa(&secret_key, message);

        println!("Signature r: {:?}", sig.r);
        println!("Signature s: {:?}", sig.s);

        let public_key = PublicKey::from_sk(&secret_key);

        println!("Public Key: {:?}", public_key);

        let verification_result = verify_ecdsa(&public_key, message, &sig);

        println!("Verification Result: {}", verification_result);

        assert!(verification_result);
    }

    #[test]
    fn test_verify_ecdsa() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let public_key = PublicKey::from_sk(&secret_key);
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
            &PublicKey::from_sk(&secret_key),
            message,
            &sig
        ));
    }

    #[test]
    fn test_verify_schnorr() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let public_key = PublicKey::from_sk(&secret_key);
        let message = b"test message";
        let sig = sign_schnorr(&secret_key, message);
        assert!(verify_schnorr(&public_key, message, &sig));
    }
}
