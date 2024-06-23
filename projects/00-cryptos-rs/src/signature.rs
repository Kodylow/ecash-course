use std::io::{Cursor, Read};
use std::ops::Mul;

use num_bigint::BigUint;
use num_traits::{FromPrimitive, One};

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

    // Print values for debugging
    println!("r: {}", r);
    println!("s before adjustment: {}", s);
    println!("n: {}", n);

    let s = if s > n / 2u32 { n - &s } else { s };

    // Print adjusted s
    println!("s after adjustment: {}", s);

    let s = (s + n) % n; // Ensure s is positive

    // Print final s
    println!("s final: {}", s);

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

#[test]
fn test_ecdsa() {
    use rand::Rng;

    use crate::keys::gen_key_pair;

    // let's create two identities
    let (sk1, pk1) = gen_key_pair();
    let (sk2, _pk2) = gen_key_pair();

    let message = b"user pk1 would like to pay user pk2 1 BTC kkthx";

    // an evil user2 attempts to submit the transaction to the network with some
    // totally random signature
    let mut rng = rand::thread_rng();
    let sig = Signature {
        r: BigUint::from(rng.gen::<u64>()),
        s: BigUint::from(rng.gen::<u64>()),
    };
    // a few seconds later a hero miner inspects the candidate transaction
    let is_legit = verify_ecdsa(&pk1, message, &sig);
    assert!(!is_legit);
    // unlike user2, hero miner is honest and discards the transaction, all is well

    // evil user2 does not give up and tries to sign with his key pair
    let sig = sign_ecdsa(&sk2, message);
    let is_legit = verify_ecdsa(&pk1, message, &sig);
    assert!(!is_legit);
    // denied, again!

    // lucky for user2, user1 feels sorry for them and the hardships they have been
    // through recently
    let sig = sign_ecdsa(&sk1, message);
    let is_legit = verify_ecdsa(&pk1, message, &sig);
    assert!(is_legit);
    // hero miner validates the transaction and adds it to their block
    // user2 happy, buys a Tesla, and promises to turn things around

    // the end.
}

#[test]
fn test_sig_der() {
    use crate::transaction::Tx;
    // a transaction used as an example in programming bitcoin
    let raw = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600").unwrap();
    let mut cursor = Cursor::new(&raw);
    let tx = Tx::decode(&mut cursor);
    let der = &tx.tx_ins[0].script_sig.cmds[0][..tx.tx_ins[0].script_sig.cmds[0].len() - 1]; // this is the DER signature of the first input on this tx. :-1 crops out the
                                                                                             // sighash-type byte
    let sig = Signature::decode(der); // making sure no asserts get tripped up inside this call

    // from programming bitcoin chapter 4
    let der = hex::decode("3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec").unwrap();
    let sig = Signature::decode(&der);
    assert_eq!(
        sig.r,
        BigUint::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16
        )
        .unwrap()
    );
    assert_eq!(
        sig.s,
        BigUint::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16
        )
        .unwrap()
    );

    // test that we can also recover back the same der encoding
    let der2 = sig.encode();
    assert_eq!(der, der2);
}
