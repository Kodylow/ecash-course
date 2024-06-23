const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

fn shr(x: u32, n: u32) -> u32 {
    x >> n
}

fn sig0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

fn sig1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

fn capsig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

fn capsig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn pad(mut b: Vec<u8>) -> Vec<u8> {
    let l = (b.len() * 8) as u64;
    b.push(0x80);
    while (b.len() * 8) % 512 != 448 {
        b.push(0x00);
    }
    b.extend_from_slice(&l.to_be_bytes());
    b
}

pub fn sha256(mut b: Vec<u8>) -> Vec<u8> {
    b = pad(b);
    let mut h = H0;

    for chunk in b.chunks(64) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            w[t] = u32::from_be_bytes([
                chunk[4 * t],
                chunk[4 * t + 1],
                chunk[4 * t + 2],
                chunk[4 * t + 3],
            ]);
        }
        for t in 16..64 {
            w[t] = sig1(w[t - 2])
                .wrapping_add(w[t - 7])
                .wrapping_add(sig0(w[t - 15]))
                .wrapping_add(w[t - 16]);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h7 = h[7];

        for t in 0..64 {
            let t1 = h7
                .wrapping_add(capsig1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = capsig0(a).wrapping_add(maj(a, b, c));
            h7 = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h7); // Update h[7] with h7
    }

    h.iter().flat_map(|&x| x.to_be_bytes()).collect()
}

// Double SHA-256 hash for transaction Ids
pub fn hash256(input: Vec<u8>) -> Vec<u8> {
    sha256(sha256(input))
}

#[test]
fn test_sha256() {
    use std::io::Read;

    use sha2::{Digest, Sha256};

    let test_bytes = vec![
        b"".to_vec(),
        b"abc".to_vec(),
        b"hello".to_vec(),
        b"a longer message to make sure that a larger number of blocks works okay too"
            .repeat(15)
            .bytes()
            .collect::<Result<Vec<u8>, _>>()
            .unwrap(),
    ];

    for b in test_bytes {
        let mut hasher = Sha256::new();
        hasher.update(b.clone());
        let gt = hasher.finalize();
        let yolo = sha256(b.clone());
        assert_eq!(gt.as_slice(), yolo.as_slice());
    }
}
