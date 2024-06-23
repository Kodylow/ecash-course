use num_bigint::BigUint;
use num_traits::Num;
use once_cell::sync::Lazy;

use crate::curves::{Curve, Generator, Point};

// Bitcoin-specific functions, classes, utilities and parameters

// Public API
pub static BITCOIN: Lazy<Coin> = Lazy::new(|| Coin { gen: bitcoin_gen() });

// Coin struct
#[derive(Debug, Clone)]
pub struct Coin {
    pub gen: Generator,
}

// Bitcoin generator function
#[allow(non_snake_case)]
fn bitcoin_gen() -> Generator {
    // Bitcoin uses secp256k1: http://www.oid-info.com/get/1.3.132.0.10
    let p = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();
    let a = BigUint::from_str_radix(
        "0000000000000000000000000000000000000000000000000000000000000000",
        16,
    )
    .unwrap();
    let b = BigUint::from_str_radix(
        "0000000000000000000000000000000000000000000000000000000000000007",
        16,
    )
    .unwrap();
    let Gx = BigUint::from_str_radix(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let Gy = BigUint::from_str_radix(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        16,
    )
    .unwrap();
    let n = BigUint::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();
    let curve = Curve { p, a, b };
    let G = Point {
        curve: curve.clone(),
        x: Some(Gx),
        y: Some(Gy),
    };
    Generator { G, n }
}
