use std::ops::{Add, Mul, Neg, Rem, Sub};
use std::str::FromStr;

use primitive_types::U256;

#[derive(Clone, Debug, PartialOrd)]
pub struct RU256 {
    pub v: U256,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RU256ParseError;

impl FromStr for RU256 {
    type Err = RU256ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // conversion from a hex string
        RU256::from_str_radix(s, 16)
    }
}

impl ToString for RU256 {
    fn to_string(&self) -> String {
        let mut bytes: [u8; 32] = [0; 32];
        self.v.to_big_endian(&mut bytes);
        hex::encode(bytes)
    }
}

impl PartialEq for RU256 {
    fn eq(&self, other: &Self) -> bool {
        return self.v == other.v;
    }
}

impl Add for RU256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self { v: self.v + rhs.v }
    }
}

impl Mul for RU256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self { v: self.v * rhs.v }
    }
}

impl Neg for RU256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            v: U256::zero() - self.v,
        }
    }
}

impl Rem<RU256> for RU256 {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        Self { v: self.v % rhs.v }
    }
}

impl RU256 {
    /// RU256 from byte slice
    pub fn from_bytes(byte_slice: &[u8]) -> Self {
        assert!(byte_slice.len() <= 32);
        Self {
            v: U256::from_big_endian(byte_slice),
        }
    }

    /// RU256 from number string
    pub fn from_str_radix(s: &str, radix: u32) -> Result<Self, RU256ParseError> {
        U256::from_str_radix(s, radix)
            .map(|n| Self { v: n })
            .map_err(|_| RU256ParseError)
    }

    pub fn from_u64(n: u64) -> Self {
        Self { v: U256::from(n) }
    }

    /// RU255 to bytes
    pub fn to_bytes(&self, bytes: &mut [u8]) {
        self.v.to_big_endian(bytes)
    }

    /// Additive Identity
    pub fn zero() -> Self {
        Self { v: U256::zero() }
    }

    /// Check if additive identity
    pub fn is_zero(&self) -> bool {
        self.v.is_zero()
    }

    /// Multiplicative Identity
    pub fn one() -> Self {
        Self { v: U256::one() }
    }

    pub fn add_mod(&self, b: &RU256, p: &RU256) -> Self {
        // Calculate x1 and x2 as the values of self and b modulo p
        let x1 = self.v % p.v;
        let x2 = b.v % p.v;

        // Attempt to add x1 and x2
        let (mut x3, overflow) = x1.overflowing_add(x2);

        // If there's an overflow or x3 is greater than or equal to p, adjust x3
        if overflow || x3 >= p.v {
            x3 = x3.overflowing_sub(p.v).0;
        }

        // Return the new RU256 instance with the result value
        Self { v: x3 }
    }

    /// Modular subtraction
    pub fn sub_mod(&self, b: &RU256, p: &RU256) -> Self {
        let x1 = self.v % p.v;
        let x2 = b.v % p.v;
        let x3 = if x1 >= x2 {
            (x1 - x2) % p.v
        } else {
            (p.v - (x2 - x1)) % p.v
        };

        Self { v: x3 }
    }

    /// Modular multiplication
    pub fn mul_mod(&self, b: &RU256, p: &RU256) -> Self {
        let x1 = self.v % p.v;
        let x2 = b.v % p.v;
        let mut result = Self::zero();
        let mut adder = Self { v: x2 };

        for i in 0..x1.bits() {
            if x1.bit(i) {
                result = result.add_mod(&adder, &p);
            }
            adder = adder.add_mod(&adder, &p);
        }

        result
    }

    /// Modular exponentiation
    pub fn exp_mod(&self, e: &RU256, p: &RU256) -> Self {
        let mut result = Self::one();
        let mut multiplier = Self { v: self.v % p.v };

        for i in 0..e.v.bits() {
            if e.v.bit(i) {
                result = result.mul_mod(&multiplier, &p);
            }
            multiplier = multiplier.mul_mod(&multiplier, &p);
        }

        result
    }

    /// Modular division
    pub fn div_mod(&self, b: &RU256, p: &RU256) -> Self {
        assert!(p.v > U256::from(2));
        let b_inv = b.exp_mod(&RU256 { v: p.v - 2 }, &p);
        self.mul_mod(&b_inv, &p)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::ru256::RU256;

    #[test]
    fn ru256_addition_case_1() {
        let a = RU256::from_str("0xBD").unwrap();
        let b = RU256::from_str("0x2B").unwrap();
        let p = RU256::from_str("0xB").unwrap();

        let r = a.add_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn ru256_addition_case_2() {
        let a = RU256::from_str("0xa167f055ff75c").unwrap();
        let b = RU256::from_str("0xacc457752e4ed").unwrap();
        let p = RU256::from_str("0xf9cd").unwrap();

        let r = a.add_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "0000000000000000000000000000000000000000000000000000000000006bb0"
        );
    }

    #[test]
    fn ru256_addition_case_3() {
        let a = RU256::from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E")
            .unwrap();
        let b = RU256::from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E")
            .unwrap();
        let p = RU256::from_str("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
            .unwrap();

        let r = a.add_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d"
        );
    }

    #[test]
    fn ru256_subtraction_case_1() {
        let a = RU256::from_str("0x1ce606").unwrap(); // a = 189389.unwrap();
        let b = RU256::from_str("0xacc12484").unwrap(); // b = 289833894.unwrap();
        let p = RU256::from_str("0xf3fa3").unwrap(); // p = 99933.unwrap();

        let r = a.sub_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "000000000000000000000000000000000000000000000000000000000009645b"
        );
    }

    #[test]
    fn ru256_subtraction_case_2() {
        let a = RU256::from_str("0xacc12484").unwrap(); // a = 289833894.unwrap();
        let b = RU256::from_str("0x1ce606").unwrap(); // b = 189389.unwrap();
        let p = RU256::from_str("0xf3fa3").unwrap(); // p = 99933.unwrap();

        let r = a.sub_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "000000000000000000000000000000000000000000000000000000000005db48"
        );
    }

    #[test]
    fn ru256_multiplication_case() {
        let a = RU256::from_str("0xa167f055ff75c").unwrap(); // a = 283948457393954.unwrap();
        let b = RU256::from_str("0xacc457752e4ed").unwrap(); // b = 303934849383754.unwrap();
        let p = RU256::from_str("0xf9cd").unwrap(); // p = 6394.unwrap();

        let r = a.mul_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "000000000000000000000000000000000000000000000000000000000000e116"
        );
    }

    #[test]
    fn ru256_exponentiation_case() {
        let a = RU256::from_str("0x1ce606").unwrap(); // a = 189389.unwrap();
        let b = RU256::from_str("0xacc12484").unwrap(); // b = 289833894.unwrap();
        let p = RU256::from_str("0xf3fa3").unwrap(); // p = 99933.unwrap();

        let r = a.exp_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "000000000000000000000000000000000000000000000000000000000002a0fd"
        );
    }

    #[test]
    fn ru256_division_case() {
        let a = RU256::from_str("0x1ce606").unwrap(); // a = 189389.unwrap();
        let b = RU256::from_str("0xacc12484").unwrap(); // b = 289833894.unwrap();
        let p = RU256::from_str("0xf3fa3").unwrap(); // p = 99933.unwrap();

        let r = a.div_mod(&b, &p);

        assert_eq!(
            r.to_string(),
            "0000000000000000000000000000000000000000000000000000000000061f57"
        );
    }
}
