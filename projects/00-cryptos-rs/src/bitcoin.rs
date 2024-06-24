use once_cell::sync::Lazy;

use crate::ru256::RU256;
use crate::secp256k1::{Point, SECP256K1};

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
    let p = SECP256K1::p();
    let a = RU256::zero();
    let b = RU256::from_u64(7);
    let G = SECP256K1::g();
    let n = SECP256K1::n();
    Generator { G, n }
}

// Curve struct
#[derive(Debug, Clone)]
pub struct Curve {
    pub p: RU256,
    pub a: RU256,
    pub b: RU256,
}

// Generator struct
#[derive(Debug, Clone)]
pub struct Generator {
    pub G: Point,
    pub n: RU256,
}
