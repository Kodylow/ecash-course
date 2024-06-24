use std::ops::{Add, Mul, Neg, Shr};

use bitcoin_num::uint::Uint256;
use once_cell::sync::Lazy;

// Core functions for math over Elliptic Curves over Finite Fields,
// especially the ability to define Points on Curves and perform
// addition and scalar multiplication.

// Power function for Uint256
pub fn pow(base: &Uint256, exp: u32) -> Uint256 {
    let mut result = Uint256::from_u64(1).unwrap();
    let mut base = base.clone();
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = result * base.clone();
        }
        base = base.clone() * base;
        exp /= 2;
    }
    result
}

// Modular Power function
pub fn mod_pow(base: &Uint256, exp: &Uint256, modulus: &Uint256) -> Uint256 {
    let mut result = Uint256::from_u64(1).unwrap();
    let mut base = base.clone();
    let mut exp = exp.clone();

    while exp > Uint256::from_u64(0).unwrap() {
        if exp & Uint256::from_u64(1).unwrap() != Uint256::from_u64(0).unwrap() {
            result = result * base.clone() % *modulus;
        }
        base = base.clone() * base % *modulus;
        exp = exp.shr(1);
    }
    result
}

// Extended Euclidean Algorithm
pub fn extended_euclidean_algorithm(a: &Uint256, b: &Uint256) -> (Uint256, Uint256, Uint256) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (Uint256::from_u64(1).unwrap(), Uint256::from_u64(0).unwrap());
    let (mut old_t, mut t) = (Uint256::from_u64(0).unwrap(), Uint256::from_u64(1).unwrap());

    while r != Uint256::from_u64(0).unwrap() {
        let quotient = old_r.clone() / r.clone();
        old_r = old_r - quotient.clone() * r.clone();
        std::mem::swap(&mut old_r, &mut r);
        old_s = old_s - quotient.clone() * s.clone();
        std::mem::swap(&mut old_s, &mut s);
        old_t = old_t - quotient.clone() * t.clone();
        std::mem::swap(&mut old_t, &mut t);
    }
    (old_r, old_s, old_t)
}

// Modular multiplicative inverse
pub fn inv(n: &Uint256, p: &Uint256) -> Uint256 {
    let (_, x, _) = extended_euclidean_algorithm(n, p);
    (x + *p) % *p
}

// Elliptic Curve over the field of integers modulo a prime
#[derive(Debug, Clone, PartialEq)]
pub struct Curve {
    pub p: Uint256,
    pub a: Uint256,
    pub b: Uint256,
}

// An integer point (x, y) on a Curve
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub curve: Curve,
    pub x: Option<Uint256>,
    pub y: Option<Uint256>,
}

impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        if self == *INF {
            return other;
        }
        if other == *INF {
            return self;
        }
        if self.x == other.x && self.y != other.y {
            return INF.clone();
        }

        let m = if self.x == other.x {
            (Uint256::from_u64(3).unwrap() * pow(self.x.as_ref().unwrap(), 2)
                + self.curve.a.clone())
                * inv(
                    &(Uint256::from_u64(2).unwrap() * *self.y.as_ref().unwrap()),
                    &self.curve.p,
                )
        } else {
            (*self.y.as_ref().unwrap() - *other.y.as_ref().unwrap())
                * inv(
                    &(*self.x.as_ref().unwrap() - *other.x.as_ref().unwrap()),
                    &self.curve.p,
                )
        };

        let rx =
            (pow(&m, 2) - *self.x.as_ref().unwrap() - *other.x.as_ref().unwrap()) % self.curve.p;
        let ry = (self.curve.p
            - (m * (rx - *self.x.as_ref().unwrap()) + *self.y.as_ref().unwrap()))
            % self.curve.p;

        Point {
            curve: self.curve.clone(),
            x: Some(rx),
            y: Some(ry),
        }
    }
}

impl Neg for Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point {
            curve: self.curve.clone(),
            x: self.x,
            y: self.y.map(|y| (self.curve.p - y) % self.curve.p), // Negate y modulo p
        }
    }
}

impl Mul<Uint256> for Point {
    type Output = Point;

    fn mul(self, mut k: Uint256) -> Point {
        assert!(k >= Uint256::from_u64(0).unwrap());
        let mut result = INF.clone();
        let mut append = self;

        while k != Uint256::from_u64(0).unwrap() {
            if k & Uint256::from_u64(1).unwrap() != Uint256::from_u64(0).unwrap() {
                result = result + append.clone();
            }
            append = append.clone() + append;
            k = k.shr(1);
        }
        result
    }
}

// A generator over a curve: an initial point and the (pre-computed) order
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Generator {
    pub G: Point,
    pub n: Uint256,
}

pub static INF: Lazy<Point> = Lazy::new(|| Point {
    curve: Curve {
        p: Uint256::from_u64(0).unwrap(),
        a: Uint256::from_u64(0).unwrap(),
        b: Uint256::from_u64(0).unwrap(),
    },
    x: None,
    y: None,
});
