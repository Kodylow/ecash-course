use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use hex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    // Initialize secp256k1 context
    let secp = Secp256k1::new();

    // Path to the precomputed points file
    let path = "/Users/kody/Documents/github/fedi_stuff/ecash-course/projects/00-cryptos-rs/precomputed_points.txt";

    // Open the file
    if let Ok(file) = File::open(path) {
        let reader = io::BufReader::new(file);

        for (index, line) in reader.lines().enumerate() {
            if let Ok(line) = line {
                // Split the line into index and point
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() != 2 {
                    eprintln!("Invalid line format at line {}", index + 1);
                    continue;
                }

                let index_str = parts[0];
                let point_str = parts[1];

                if let Ok(index) = index_str.parse::<usize>() {
                    match PublicKey::from_slice(&hex::decode(point_str).expect("Invalid hex")) {
                        Ok(public_key) => {
                            // Recompute the expected point using secp256k1
                            let a = (index % 256) as u64;
                            let b = (index / 256) as u32;
                            let scalar = a * 256u64.pow(b);
                            let mut scalar_bytes = [0u8; 32];
                            scalar_bytes[24..].copy_from_slice(&scalar.to_be_bytes());
                            let secret_key = SecretKey::from_slice(&scalar_bytes).unwrap();
                            let expected_point = PublicKey::from_secret_key(&secp, &secret_key);

                            if public_key == expected_point {
                                println!("Point {} is valid", index);
                            } else {
                                println!("Point {} is invalid", index);
                            }
                        }
                        Err(_) => println!("Point {} is invalid", index),
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to open the file: {}", path);
    }
}
