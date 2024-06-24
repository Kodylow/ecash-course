use std::ops::{Add, Mul, Neg, Shr};

use once_cell::sync::Lazy;
use primitive_types::U256;

// Core functions for math over Elliptic Curves over Finite Fields,
// especially the ability to define Points on Curves and perform
// addition and scalar multiplication.

// Extended Euclidean Algorithm
fn extended_euclidean_algorithm(a: U256, b: U256) -> (U256, i128, i128) {
    let (mut last_r, mut r) = (a, b);
    let (mut last_s, mut s) = (1, 0);
    let (mut last_t, mut t) = (0, 1);

    while r > U256::from(0) {
        let quo = last_r / r;
        let new_r = last_r - quo * r;
        last_r = std::mem::replace(&mut r, new_r);
        let new_s = last_s - quo.as_u128() as i128 * s;
        last_s = std::mem::replace(&mut s, new_s);
        let new_t = last_t - quo.as_u128() as i128 * t;
        last_t = std::mem::replace(&mut t, new_t);
    }

    (last_r, last_s, last_t)
}

// Modular multiplicative inverse
pub fn inv(n: U256, p: U256) -> U256 {
    let (_, mut x, _) = extended_euclidean_algorithm(n, p);
    if x < 0 {
        x += p.as_u128() as i128;
    }
    U256::from(x as u128) % p
}

// Elliptic Curve over the field of integers modulo a prime
#[derive(Debug, Clone, PartialEq)]
pub struct Curve {
    pub p: U256,
    pub a: U256,
    pub b: U256,
}

// An integer point (x, y) on a Curve
#[derive(Debug, Clone, PartialEq)]
pub struct Point {
    pub curve: Curve,
    pub x: Option<U256>,
    pub y: Option<U256>,
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

        let p = &self.curve.p;

        let m = if self.x == other.x {
            let numerator = (U256::from(3) * self.x.as_ref().unwrap().pow(U256::from(2))
                + self.curve.a.clone())
                % p;
            let denominator = (U256::from(2) * *self.y.as_ref().unwrap()) % p;
            println!(
                "Doubling: numerator = {}, denominator = {}",
                numerator, denominator
            );
            (numerator * inv(denominator, *p)) % p
        } else {
            let numerator = (*self.y.as_ref().unwrap() + p - *other.y.as_ref().unwrap()) % p;
            let denominator = (*self.x.as_ref().unwrap() + p - *other.x.as_ref().unwrap()) % p;
            println!(
                "Addition: numerator = {}, denominator = {}",
                numerator, denominator
            );
            (numerator * inv(denominator, *p)) % p
        };

        let rx = (m.pow(U256::from(2)) + p - *self.x.as_ref().unwrap() + p
            - *other.x.as_ref().unwrap())
            % p;
        let ry =
            (m * (*self.x.as_ref().unwrap() + p - rx.clone()) + p - *self.y.as_ref().unwrap()) % p;

        println!("Resulting point: rx = {}, ry = {}", rx, ry);

        Point {
            curve: self.curve.clone(),
            x: Some(rx),
            y: Some(ry),
        }
    }
}

impl Mul<U256> for Point {
    type Output = Point;

    fn mul(self, mut k: U256) -> Point {
        assert!(k >= U256::from(0));
        let mut result = INF.clone();
        let mut append = self.clone();

        while k != U256::from(0) {
            println!("k: {}", k);
            if k & U256::from(1) != U256::from(0) {
                result = result + append.clone();
                println!("result after addition: {:?}", result);
            }
            append = append.clone() + append;
            println!("append after doubling: {:?}", append);
            k = k.shr(1);
        }

        // Ensure the result is within the field
        let p = &self.curve.p;
        Point {
            curve: result.curve.clone(),
            x: result.x.map(|x| x % p),
            y: result.y.map(|y| y % p),
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

// A generator over a curve: an initial point and the (pre-computed) order
#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct Generator {
    pub G: Point,
    pub n: U256,
}

pub static INF: Lazy<Point> = Lazy::new(|| Point {
    curve: Curve {
        p: U256::from(0),
        a: U256::from(0),
        b: U256::from(0),
    },
    x: None,
    y: None,
});

#[test]
fn test_extended_euclidean_algorithm() {
    let a = U256::from(240);
    let b = U256::from(46);
    let (gcd, mut x, y) = extended_euclidean_algorithm(a, b);
    if x < 0 {
        x += b.as_u128() as i128;
    }
    println!("gcd: {}, x: {}, y: {}", gcd, x, y);
    assert_eq!(gcd, U256::from(2));
    assert_eq!((a * U256::from(x as u128) + b * U256::from(y)) % b, gcd % b);
}

#[test]
fn test_inv() {
    let n = U256::from(3);
    let p = U256::from(11);
    let inv_n = inv(n, p);
    assert_eq!((n * inv_n) % p, U256::from(1));
}

#[test]
fn test_point_addition() {
    let curve = Curve {
        p: U256::from(17),
        a: U256::from(2),
        b: U256::from(2),
    };
    let p1 = Point {
        curve: curve.clone(),
        x: Some(U256::from(1)),
        y: Some(U256::from(2)),
    };
    let p2 = Point {
        curve: curve.clone(),
        x: Some(U256::from(3)),
        y: Some(U256::from(4)),
    };
    let result = p1 + p2;
    assert_eq!(
        result,
        Point {
            curve: curve.clone(),
            x: Some(U256::from(14)),
            y: Some(U256::from(2)),
        }
    );
}

#[test]
fn test_point_doubling() {
    let curve = Curve {
        p: U256::from(17),
        a: U256::from(2),
        b: U256::from(2),
    };
    let p = Point {
        curve: curve.clone(),
        x: Some(U256::from(5)),
        y: Some(U256::from(1)),
    };
    let result = p.clone() + p;
    assert_eq!(result.x, Some(U256::from(6)));
    assert_eq!(result.y, Some(U256::from(3)));
}

#[test]
fn test_point_negation() {
    let curve = Curve {
        p: U256::from(17),
        a: U256::from(2),
        b: U256::from(2),
    };
    let p = Point {
        curve: curve.clone(),
        x: Some(U256::from(5)),
        y: Some(U256::from(1)),
    };
    let neg_p = -p.clone();
    assert_eq!(neg_p.x, p.x);
    assert_eq!(neg_p.y, Some(U256::from(16))); // 17 - 1 = 16
}

#[test]
fn test_point_multiplication() {
    let curve = Curve {
        p: U256::from(17),
        a: U256::from(2),
        b: U256::from(2),
    };
    let p = Point {
        curve: curve.clone(),
        x: Some(U256::from(5)),
        y: Some(U256::from(1)),
    };
    let result = p * U256::from(2);
    assert_eq!(result.x, Some(U256::from(6)));
    assert_eq!(result.y, Some(U256::from(3)));
}

#[test]
fn test_bitcoin_curve() {
    // secp256k1 curve parameters
    let p = U256::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        16,
    )
    .unwrap();
    let a = U256::from(0);
    let b = U256::from(7);

    let curve = Curve { p, a, b };

    // Private key
    let privkey = U256::from_str_radix(
        "9088a0bc08c31d64a3b59f64b19fbeec5b3e6d757909687293c23c3cc370e32e",
        16,
    )
    .unwrap();

    // Public key
    let pubkey_x = U256::from_str_radix(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let pubkey_y = U256::from_str_radix(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .unwrap();

    let pubkey_point = Point {
        curve: curve.clone(),
        x: Some(pubkey_x),
        y: Some(pubkey_y),
    };

    // Generator point for secp256k1
    let g_x = U256::from_str_radix(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        16,
    )
    .unwrap();
    let g_y = U256::from_str_radix(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        16,
    )
    .unwrap();

    let g = Point {
        curve: curve.clone(),
        x: Some(g_x),
        y: Some(g_y),
    };

    // Debug prints
    println!("Curve: {:?}", curve);
    println!("Private key: {:?}", privkey);
    println!("Public key point: {:?}", pubkey_point);
    println!("Generator point: {:?}", g);

    // Calculate the public key from the private key
    let calculated_pubkey = g * privkey;

    println!("Calculated public key: {:?}", calculated_pubkey);

    assert_eq!(calculated_pubkey, pubkey_point);
}
