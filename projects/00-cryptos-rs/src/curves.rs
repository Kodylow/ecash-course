use std::ops::{Add, Mul, Neg};

use num_bigint::BigUint;
use num_traits::{One, Zero};
use once_cell::sync::Lazy;

// Core functions for math over Elliptic Curves over Finite Fields,
// especially the ability to define Points on Curves and perform
// addition and scalar multiplication.

// Extended Euclidean Algorithm
pub fn extended_euclidean_algorithm(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (BigUint::one(), BigUint::zero());
    let (mut old_t, mut t) = (BigUint::zero(), BigUint::one());
    while r != BigUint::zero() {
        let quotient = &old_r / &r;
        old_r = &old_r - &quotient * &r;
        std::mem::swap(&mut old_r, &mut r);
        old_s = &old_s - &quotient * &s;
        std::mem::swap(&mut old_s, &mut s);
        old_t = &old_t - &quotient * &t;
        std::mem::swap(&mut old_t, &mut t);
    }
    (old_r, old_s, old_t)
}

// Modular multiplicative inverse
pub fn inv(n: &BigUint, p: &BigUint) -> BigUint {
    let (_, x, _) = extended_euclidean_algorithm(n, p);
    (x % p + p) % p
}

// Elliptic Curve over the field of integers modulo a prime
#[derive(Debug, Clone, PartialEq)]
pub struct Curve {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
}

// An integer point (x, y) on a Curve
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub curve: Curve,
    pub x: Option<BigUint>,
    pub y: Option<BigUint>,
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
            (BigUint::from(3u32) * self.x.as_ref().unwrap().pow(2) + &self.curve.a)
                * inv(
                    &(BigUint::from(2u32) * self.y.as_ref().unwrap()),
                    &self.curve.p,
                )
        } else {
            (self.y.as_ref().unwrap() - other.y.as_ref().unwrap())
                * inv(
                    &(self.x.as_ref().unwrap() - other.x.as_ref().unwrap()),
                    &self.curve.p,
                )
        };

        let rx = (m.pow(2) - self.x.as_ref().unwrap() - other.x.as_ref().unwrap()) % &self.curve.p;
        let ry = (&self.curve.p
            - (m * (&rx - self.x.as_ref().unwrap()) + self.y.as_ref().unwrap()))
            % &self.curve.p;

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
            y: self.y.map(|y| (&self.curve.p - y) % &self.curve.p), // Negate y modulo p
        }
    }
}

impl Mul<BigUint> for Point {
    type Output = Point;

    fn mul(self, mut k: BigUint) -> Point {
        assert!(k >= BigUint::zero());
        let mut result = INF.clone();
        let mut append = self;

        while k != BigUint::zero() {
            if &k & BigUint::one() != BigUint::zero() {
                result = result + append.clone();
            }
            append = append.clone() + append;
            k >>= 1;
        }
        result
    }
}

// A generator over a curve: an initial point and the (pre-computed) order
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Generator {
    pub G: Point,
    pub n: BigUint,
}

pub static INF: Lazy<Point> = Lazy::new(|| Point {
    curve: Curve {
        p: BigUint::zero(),
        a: BigUint::zero(),
        b: BigUint::zero(),
    },
    x: None,
    y: None,
});
