use std::io::{Cursor, Read};

use bitcoin_num::uint::Uint256;
use once_cell::sync::Lazy;

use crate::curves::pow;
use crate::{sha256, utils};

static GENESIS_BLOCK_MAIN: Lazy<Vec<u8>> = Lazy::new(|| {
    hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap()
});

static GENESIS_BLOCK_TEST: Lazy<Vec<u8>> = Lazy::new(|| {
    hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18").unwrap()
});
fn decode_int(s: &mut Cursor<&Vec<u8>>, nbytes: usize) -> u32 {
    let mut buf = vec![0; nbytes];
    s.read_exact(&mut buf).unwrap();
    u32::from_le_bytes(buf.try_into().unwrap())
}

fn encode_int(i: u32, nbytes: usize) -> Vec<u8> {
    i.to_le_bytes()[..nbytes].to_vec()
}

fn bits_to_target(bits: &[u8]) -> Uint256 {
    let exponent = bits[3];
    let mut coeff_bytes = bits[..3].to_vec();
    coeff_bytes.reverse();
    let mut coeff_array = [0u8; 32];
    coeff_array[..coeff_bytes.len()].copy_from_slice(&coeff_bytes);
    let coeff = Uint256::from_be_bytes(coeff_array);
    coeff * pow(&Uint256::from_u64(256u64).unwrap(), (exponent - 3) as u32)
}

fn target_to_bits(target: Uint256) -> Vec<u8> {
    let b_u64 = target.to_bytes();
    let mut b = b_u64
        .iter()
        .flat_map(|&x| x.to_le_bytes())
        .collect::<Vec<u8>>();
    while b.len() > 1 && b[0] == 0 {
        b.remove(0);
    }
    let exponent = b.len() as u8;
    let coeff = if b.len() >= 3 {
        b[..3].to_vec()
    } else {
        let mut v = b.clone();
        v.resize(3, 0);
        v
    };

    let mut new_bits = coeff;
    new_bits.reverse(); // Ensure the coefficient is in little-endian order
    new_bits.push(exponent);
    new_bits
}

fn calculate_new_bits(prev_bits: &[u8], dt: u64) -> Vec<u8> {
    let two_weeks = 60 * 60 * 24 * 14;
    let dt = dt.clamp(two_weeks / 4, two_weeks * 4);
    let prev_target = bits_to_target(prev_bits);
    let new_target = (prev_target * Uint256::from_u64(dt).unwrap()
        / Uint256::from_u64(two_weeks).unwrap())
    .min(Uint256::from_u64(0xffff).unwrap() * pow(&Uint256::from_u64(256).unwrap(), (0x1d - 3)));

    let mut new_bits = target_to_bits(new_target);
    if new_bits.len() < 4 {
        new_bits.resize(4, 0);
    }
    new_bits
}

#[derive(Debug, Clone)]
struct Block {
    version: u32,
    prev_block: Vec<u8>,
    merkle_root: Vec<u8>,
    timestamp: u32,
    bits: Vec<u8>,
    nonce: Vec<u8>,
}

impl Block {
    fn decode(s: &mut Cursor<&Vec<u8>>) -> Block {
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
        let mut result = sha256::hash256(self.encode());
        result.reverse();
        hex::encode(result)
    }

    fn target(&self) -> Uint256 {
        bits_to_target(&self.bits)
    }

    fn difficulty(&self) -> Uint256 {
        let genesis_block_target =
            Uint256::from_u64(0xffff).unwrap() * pow(&Uint256::from_u64(256).unwrap(), (0x1d - 3));
        let target = self.target();
        let difficulty = genesis_block_target / target;
        difficulty
    }

    fn validate(&self) -> bool {
        let header_vec = hex::decode(&self.id()).unwrap();
        let header: [u8; 32] = header_vec.try_into().unwrap();
        let header = Uint256::from_be_bytes(header);
        let target = self.target();

        if header >= target {
            return false;
        }

        true
    }
}

#[test]
fn test_block() {
    let raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
    println!("Raw block data: {}", hex::encode(&raw));
    let mut cursor = Cursor::new(&raw);
    let block = Block::decode(&mut cursor);
    println!("Decoded block: {:?}", block);

    assert_eq!(block.version, 0x20000002);
    assert_eq!(
        block.prev_block,
        hex::decode("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e").unwrap()
    );
    assert_eq!(
        block.merkle_root,
        hex::decode("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b").unwrap()
    );
    assert_eq!(block.timestamp, 0x59a7771e);
    assert_eq!(block.bits, hex::decode("e93c0118").unwrap());
    assert_eq!(block.nonce, hex::decode("a4ffd71d").unwrap());

    let raw2 = block.encode();
    println!("Encoded block data: {}", hex::encode(&raw2));
    assert_eq!(raw, raw2);

    let block_id = block.id();
    println!("Block ID: {}", block_id);
    assert_eq!(
        block_id,
        "0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523"
    );

    let target = block.target();
    println!("Block target: {:?}", target);
    assert_eq!(
        target,
        Uint256::from_be_bytes(
            hex::decode("0000000000000000013ce9000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap()
        )
    );

    let difficulty = block.difficulty();
    println!("Block difficulty: {}", difficulty);
    assert_eq!(difficulty, Uint256::from_u64(888171856257).unwrap());
}

#[test]
fn test_validate() {
    let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1").unwrap();
    println!("Raw block data for validation: {}", hex::encode(&raw));
    let mut cursor = Cursor::new(&raw);
    let block = Block::decode(&mut cursor);
    println!("Decoded block for validation: {:?}", block);
    assert!(block.validate());

    let raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0").unwrap();
    println!("Raw block data for invalidation: {}", hex::encode(&raw));
    let mut cursor = Cursor::new(&raw);
    let block = Block::decode(&mut cursor);
    println!("Decoded block for invalidation: {:?}", block);
    assert!(!block.validate());
}

#[test]
fn test_calculate_bits() {
    let dt = 302400;
    let prev_bits = hex::decode("54d80118").unwrap();
    let next_bits = calculate_new_bits(&prev_bits, dt);
    assert_eq!(next_bits, hex::decode("00157617").unwrap());

    for bits in [&prev_bits, &next_bits] {
        let target = bits_to_target(bits);
        let bits2 = target_to_bits(target.clone());
        assert_eq!(bits, &bits2);
    }
}

#[test]
fn test_genesis_block() {
    let block_bytes = GENESIS_BLOCK_MAIN.to_vec();
    println!("Genesis block bytes: {}", hex::encode(&block_bytes));
    assert_eq!(block_bytes.len(), 80);
    let mut cursor = Cursor::new(&block_bytes);
    let block = Block::decode(&mut cursor);
    let block_clone = block.clone();

    println!("Decoded genesis block: {:?}", block);
    assert_eq!(block.version, 1);
    assert_eq!(block.prev_block, vec![0; 32]);
    assert_eq!(
        hex::encode(&block.merkle_root),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
    assert_eq!(block.timestamp, 1231006505);
    assert_eq!(
        hex::encode(&block.bits.iter().rev().cloned().collect::<Vec<u8>>()),
        "1d00ffff"
    );
    assert_eq!(
        u32::from_le_bytes(block.nonce.try_into().unwrap()),
        2083236893
    );

    let block_id = block_clone.id();
    println!("Genesis block ID: {}", block_id);
    assert_eq!(
        block_id,
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );

    let target = block_clone.target();
    println!("Genesis block target: {:?}", target);
    assert_eq!(
        format!("{:?}", target),
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    );

    let validation = block_clone.validate();
    println!("Genesis block validation: {}", validation);
    assert!(validation);
}
