use std::io::{Cursor, Read};

use crate::{sha256, utils};

const GENESIS_BLOCK_MAIN: &[u8] = b"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff01d1dac2b7c";
const GENESIS_BLOCK_TEST: &[u8] = b"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18";

fn decode_int(s: &mut Cursor<&[u8]>, nbytes: usize) -> u32 {
    let mut buf = vec![0; nbytes];
    s.read_exact(&mut buf).unwrap();
    u32::from_le_bytes(buf.try_into().unwrap())
}

fn encode_int(i: u32, nbytes: usize) -> Vec<u8> {
    i.to_le_bytes()[..nbytes].to_vec()
}

fn bits_to_target(bits: &[u8]) -> u128 {
    let exponent = bits[3];
    let coeff = u128::from_le_bytes(bits[..3].try_into().unwrap());
    coeff * 256u128.pow((exponent - 3) as u32)
}

fn target_to_bits(target: u128) -> Vec<u8> {
    let mut b = target.to_be_bytes().to_vec();
    while b[0] == 0 {
        b.remove(0);
    }
    let exponent = b.len() as u8;
    let coeff = if b[0] >= 128 {
        vec![0, b[0], b[1]]
    } else {
        b[..3].to_vec()
    };
    let mut new_bits = coeff;
    new_bits.reverse();
    new_bits.push(exponent);
    new_bits
}

fn calculate_new_bits(prev_bits: &[u8], dt: u32) -> Vec<u8> {
    let two_weeks = 60 * 60 * 24 * 14;
    let dt = dt.clamp(two_weeks / 4, two_weeks * 4);
    let prev_target = bits_to_target(prev_bits);
    let new_target =
        (prev_target * dt as u128 / two_weeks as u128).min(0xffff * 256u128.pow(0x1d - 3));
    target_to_bits(new_target)
}

#[derive(Debug)]
struct Block {
    version: u32,
    prev_block: Vec<u8>,
    merkle_root: Vec<u8>,
    timestamp: u32,
    bits: Vec<u8>,
    nonce: Vec<u8>,
}

impl Block {
    fn decode(s: &mut Cursor<&[u8]>) -> Block {
        let version = decode_int(s, 4);
        let mut prev_block = vec![0; 32];
        s.read_exact(&mut prev_block).unwrap();
        prev_block.reverse();
        let mut merkle_root = vec![0; 32];
        s.read_exact(&mut merkle_root).unwrap();
        merkle_root.reverse();
        let timestamp = decode_int(s, 4);
        let mut bits = vec![0; 4];
        s.read_exact(&mut bits).unwrap();
        let mut nonce = vec![0; 4];
        s.read_exact(&mut nonce).unwrap();
        Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend(encode_int(self.version, 4));
        let mut prev_block = self.prev_block.clone();
        prev_block.reverse();
        out.extend(prev_block);
        let mut merkle_root = self.merkle_root.clone();
        merkle_root.reverse();
        out.extend(merkle_root);
        out.extend(encode_int(self.timestamp, 4));
        out.extend(&self.bits);
        out.extend(&self.nonce);
        out
    }

    fn id(&self) -> String {
        let result = sha256::hash256(self.encode());
        hex::encode(result)
    }

    fn target(&self) -> u128 {
        bits_to_target(&self.bits)
    }

    fn difficulty(&self) -> f64 {
        let genesis_block_target = 0xffff * 256u128.pow(0x1d - 3);
        genesis_block_target as f64 / self.target() as f64
    }

    fn validate(&self) -> bool {
        let block_id = u128::from_str_radix(&self.id(), 16).unwrap();
        block_id < self.target()
    }
}
