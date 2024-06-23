use std::io::{Cursor, Read};
use std::ops::Mul;

use num_bigint::BigUint;
use num_traits::One;

use crate::bitcoin::BITCOIN;
use crate::curves::inv;
use crate::keys::{gen_secret_key, PublicKey};
use crate::sha256::hash256;

// ECDSA Signature
#[derive(Debug, Clone)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
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
        let r = BigUint::from_bytes_be(&r);
        s.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], 0x02);
        s.read_exact(&mut byte).unwrap();
        let slength = byte[0];
        let mut s_vec = vec![0; slength as usize];
        s.read_exact(&mut s_vec).unwrap();
        let s = BigUint::from_bytes_be(&s_vec);
        assert_eq!(der.len(), 6 + rlength as usize + slength as usize);
        Signature { r, s }
    }

    pub fn encode(&self) -> Vec<u8> {
        fn dern(n: &BigUint) -> Vec<u8> {
            let mut nb = n.to_bytes_be();
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

pub fn sign_ecdsa(secret_key: &BigUint, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let z = BigUint::from_bytes_be(&hash256(message.to_vec()));

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let P = PublicKey::from_sk(&k);

    let r = P.x.clone().unwrap();
    let s = (inv(&k, n) * (z + secret_key * &r)) % n;
    let s = if s > n / 2u32 { n - &s } else { s };

    Signature { r, s }
}

pub fn verify_ecdsa(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= BigUint::one() && sig.r < *n);
    assert!(sig.s >= BigUint::one() && sig.s < *n);

    let z = BigUint::from_bytes_be(&hash256(message.to_vec()));

    let w = inv(&sig.s, n);
    let u1 = (&z * &w) % n;
    let u2 = (&sig.r * &w) % n;
    #[allow(non_snake_case)]
    let pubkey_point = public_key.to_point();
    #[allow(non_snake_case)]
    let P = BITCOIN.gen.G.clone().mul(u1) + pubkey_point.clone().mul(u2);
    P.x.unwrap() == sig.r
}

pub fn sign_schnorr(secret_key: &BigUint, message: &[u8]) -> Signature {
    let n = &BITCOIN.gen.n;

    let z = BigUint::from_bytes_be(&hash256(message.to_vec()));

    let k = gen_secret_key(n);
    #[allow(non_snake_case)]
    let R = PublicKey::from_sk(&k);

    let r = R.x.clone().unwrap();
    let e = BigUint::from_bytes_be(&hash256([r.to_bytes_be(), message.to_vec()].concat()));
    let s = (k + e * secret_key) % n;

    Signature { r, s }
}

pub fn verify_schnorr(public_key: &PublicKey, message: &[u8], sig: &Signature) -> bool {
    let n = &BITCOIN.gen.n;

    assert!(sig.r >= BigUint::one() && sig.r < *n);
    assert!(sig.s >= BigUint::one() && sig.s < *n);

    let e = BigUint::from_bytes_be(&hash256([sig.r.to_bytes_be(), message.to_vec()].concat()));
    #[allow(non_snake_case)]
    let pubkey_point = public_key.to_point();
    #[allow(non_snake_case)]
    let R = BITCOIN.gen.G.clone().mul(sig.s.clone()) + (-pubkey_point.clone().mul(e));

    R.x.unwrap() == sig.r
}
