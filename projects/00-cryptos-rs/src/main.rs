use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;

use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    // Initialize secp256k1 context
    let secp = Secp256k1::new();
    println!("Secp256k1 context initialized.");

    // Hard code the generator point
    let mut generator_bytes = [0u8; 65];
    generator_bytes[0] = 0x04; // Uncompressed public key prefix
    generator_bytes[1..33].copy_from_slice(&GENERATOR_X);
    generator_bytes[33..65].copy_from_slice(&GENERATOR_Y);
    let generator_point = PublicKey::from_slice(&generator_bytes).unwrap();
    println!(
        "Generator point obtained: {:?}",
        hex::encode(generator_point.serialize())
    );

    let mut precomputed_points = vec![generator_point; 256 * 32];
    println!("Initialized vector for precomputed points.");

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("/Users/kody/Documents/github/fedi_stuff/ecash-course/projects/00-cryptos-rs/precomputed_points.txt")
        .unwrap();

    // Determine the last precomputed point
    let mut last_index = 0;
    if let Ok(file) = File::open("/Users/kody/Documents/github/fedi_stuff/ecash-course/projects/00-cryptos-rs/precomputed_points.txt") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                if let Some((index_str, point_str)) = line.split_once(':') {
                    if let Ok(index) = index_str.parse::<usize>() {
                        last_index = index;
                        let point_bytes = hex::decode(point_str).unwrap();
                        precomputed_points[index] = PublicKey::from_slice(&point_bytes).unwrap();
                    }
                }
            }
        }
    }
    println!("Resuming from index: {}", last_index);

    for i in 0..256 * 32 {
        if i <= last_index {
            continue;
        }
        let mut current_point = generator_point.clone();
        for _ in 0..i {
            current_point = current_point.combine(&generator_point).unwrap();
        }
        precomputed_points[i] = current_point;
        println!(
            "Precomputed point for index {}: {:?}",
            i, precomputed_points[i]
        );

        // Write the precomputed point to file immediately
        writeln!(
            file,
            "{}:{}",
            i,
            hex::encode(precomputed_points[i].serialize())
        )
        .unwrap();
        println!(
            "Written point {} to file: {}",
            i,
            hex::encode(precomputed_points[i].serialize())
        );
    }
    println!("All precomputed points written to file successfully.");
}
