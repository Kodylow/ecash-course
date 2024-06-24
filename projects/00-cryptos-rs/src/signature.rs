use std::io::{Cursor, Read};
use std::ops::Mul;

use bitcoin_num::uint::Uint256;

use crate::bitcoin::BITCOIN;
use crate::curves::inv;
use crate::keys::{gen_secret_key, PublicKey};
use crate::sha256::hash256;

// ECDSA Signature
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub r: Uint256,
    pub s: Uint256,
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
        let r = Uint256::from_be_bytes(r.try_into().unwrap());
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x02);
        s.read_exact(&mut byte).unwrap();
        let slength = byte[0];
        let mut s_vec = vec![0; slength as usize];
        s.read_exact(&mut s_vec).unwrap();
        let s = Uint256::from_be_bytes(s_vec.try_into().unwrap());
        assert_eq!(der.len(), 6 + rlength as usize + slength as usize);
        Signature { r, s }
    }

    pub fn encode(&self) -> Vec<u8> {
        fn dern(n: &Uint256) -> Vec<u8> {
            let mut nb = n
                .to_bytes()
                .iter()
                .flat_map(|&x| x.to_be_bytes())
                .collect::<Vec<u8>>();
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

pub fn sign_ecdsa(secret_key: &Uint256, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let z = Uint256::from_be_bytes(hash256(message.to_vec()).try_into().unwrap());

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let P = PublicKey::from_sk(&k, &BITCOIN.gen);

    let r = P.0.x.clone().unwrap();
    let s = (inv(&k, n) * (z + *secret_key * r)) % *n;

    // Print values for debugging
    println!("r: {}", r);
    println!("s before adjustment: {}", s);
    println!("n: {}", n);

    let s = if s > *n / Uint256::from_u64(2).unwrap() {
        *n - s
    } else {
        s
    };

    // Print adjusted s
    println!("s after adjustment: {}", s);

    let s = (s + *n) % *n; // Ensure s is positive

    // Print final s
    println!("s final: {}", s);

    Signature { r, s }
}

pub fn verify_ecdsa(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= Uint256::from_u64(1).unwrap() && sig.r < *n);
    assert!(sig.s >= Uint256::from_u64(1).unwrap() && sig.s < *n);

    let z = Uint256::from_be_bytes(hash256(message.to_vec()).try_into().unwrap());

    let w = inv(&sig.s, n);
    let u1 = (z * w) % *n;
    let u2 = (sig.r * w) % *n;
    #[allow(non_snake_case)]
    let pubkey_point = &public_key.0;
    #[allow(non_snake_case)]
    let P = BITCOIN.gen.G.clone().mul(u1) + pubkey_point.clone().mul(u2);
    P.x.unwrap() == sig.r
}

pub fn sign_schnorr(secret_key: &Uint256, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let R = PublicKey::from_sk(&k, &BITCOIN.gen);

    let r = R.0.x.clone().unwrap();
    let mut bytes_vec = r
        .to_bytes()
        .iter()
        .flat_map(|&x| x.to_be_bytes())
        .collect::<Vec<u8>>(); // Ensure to_bytes_be() returns Vec<u8>
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = Uint256::from_be_bytes(hashed.try_into().unwrap());
    let s = (k + e * *secret_key) % *n;

    Signature { r, s }
}

pub fn verify_schnorr(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= Uint256::from_u64(1).unwrap() && sig.r < *n);
    assert!(sig.s >= Uint256::from_u64(1).unwrap() && sig.s < *n);

    let mut bytes_vec = sig
        .r
        .to_bytes()
        .iter()
        .flat_map(|&x| x.to_be_bytes())
        .collect::<Vec<u8>>(); // Ensure to_bytes_be() returns Vec<u8>
    bytes_vec.extend_from_slice(message);
    let hashed = hash256(bytes_vec);
    let e = Uint256::from_be_bytes(hashed.as_slice().try_into().unwrap());
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
        let r = Uint256::from_u64(12345).unwrap();
        let s = Uint256::from_u64(67890).unwrap();
        let sig = Signature { r, s };
        let der = sig.encode();
        let decoded_sig = Signature::decode(&der);
        assert_eq!(sig, decoded_sig);
    }

    #[test]
    fn test_sign_ecdsa() {
        let secret_key = gen_secret_key(&BITCOIN.gen.n);
        let message = b"test message";
        let sig = sign_ecdsa(&secret_key, message);
        assert!(verify_ecdsa(
            &PublicKey::from_sk(&secret_key, &BITCOIN.gen),
            message,
            &sig
        ));
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
