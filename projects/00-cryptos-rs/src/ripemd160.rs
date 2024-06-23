const K0: u32 = 0x00000000;
const K1: u32 = 0x5A827999;
const K2: u32 = 0x6ED9EBA1;
const K3: u32 = 0x8F1BBCDC;
const K4: u32 = 0xA953FD4E;
const KK0: u32 = 0x50A28BE6;
const KK1: u32 = 0x5C4DD124;
const KK2: u32 = 0x6D703EF3;
const KK3: u32 = 0x7A6D76E9;
const KK4: u32 = 0x00000000;

const PADDING: [u8; 64] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

struct RMDContext {
    state: [u32; 5],
    count: u64,
    buffer: [u8; 64],
}

impl RMDContext {
    fn new() -> Self {
        RMDContext {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            count: 0,
            buffer: [0; 64],
        }
    }
}

pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    let mut ctx = RMDContext::new();
    rmd160_update(&mut ctx, input, input.len());
    rmd160_final(&mut ctx)
}

fn rmd160_update(ctx: &mut RMDContext, input: &[u8], input_len: usize) {
    let mut have = (ctx.count / 8 % 64) as usize;
    let need = 64 - have;
    ctx.count += (input_len * 8) as u64;
    let mut off = 0;

    if input_len >= need {
        if have > 0 {
            ctx.buffer[have..have + need].copy_from_slice(&input[..need]);
            rmd160_transform(&mut ctx.state, &ctx.buffer);
            off = need;
            have = 0;
        }
        while off + 64 <= input_len {
            rmd160_transform(&mut ctx.state, &input[off..off + 64]);
            off += 64;
        }
    }

    if off < input_len {
        ctx.buffer[have..have + input_len - off].copy_from_slice(&input[off..input_len]);
    }
}

fn rmd160_final(ctx: &mut RMDContext) -> [u8; 20] {
    let size = ctx.count.to_le_bytes();
    let mut padlen = 64 - (ctx.count / 8 % 64) as usize;
    if padlen < 1 + 8 {
        padlen += 64;
    }
    rmd160_update(ctx, &PADDING, padlen - 8);
    rmd160_update(ctx, &size, 8);
    let mut digest = [0u8; 20];
    for (i, &val) in ctx.state.iter().enumerate() {
        digest[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    digest
}

fn rol(n: u32, x: u32) -> u32 {
    (x << n) | (x >> (32 - n))
}

fn f0(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn f1(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

fn f2(x: u32, y: u32, z: u32) -> u32 {
    (x | !y) ^ z
}

fn f3(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

fn f4(x: u32, y: u32, z: u32) -> u32 {
    x ^ (y | !z)
}

fn r(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
    fj: fn(u32, u32, u32) -> u32,
    kj: u32,
    sj: u32,
    rj: usize,
    x: &[u32],
) -> (u32, u32) {
    let a = rol(
        sj,
        a.wrapping_add(fj(b, c, d))
            .wrapping_add(x[rj])
            .wrapping_add(kj),
    )
    .wrapping_add(e);
    let c = rol(10, c);
    (a, c)
}

fn rmd160_transform(state: &mut [u32; 5], block: &[u8]) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes(block[i * 4..(i + 1) * 4].try_into().unwrap());
    }

    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    // Round 1
    macro_rules! round {
        ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $k:expr, $s:expr, $r:expr) => {
            let (new_a, new_c) = r($a, $b, $c, $d, $e, $f, $k, $s, $r, &x);
            $a = new_a;
            $c = new_c;
        };
    }

    round!(a, b, c, d, e, f0, K0, 11, 0);
    round!(e, a, b, c, d, f0, K0, 14, 1);
    round!(d, e, a, b, c, f0, K0, 15, 2);
    round!(c, d, e, a, b, f0, K0, 12, 3);
    round!(b, c, d, e, a, f0, K0, 5, 4);
    round!(a, b, c, d, e, f0, K0, 8, 5);
    round!(e, a, b, c, d, f0, K0, 7, 6);
    round!(d, e, a, b, c, f0, K0, 9, 7);
    round!(c, d, e, a, b, f0, K0, 11, 8);
    round!(b, c, d, e, a, f0, K0, 13, 9);
    round!(a, b, c, d, e, f0, K0, 14, 10);
    round!(e, a, b, c, d, f0, K0, 15, 11);
    round!(d, e, a, b, c, f0, K0, 6, 12);
    round!(c, d, e, a, b, f0, K0, 7, 13);
    round!(b, c, d, e, a, f0, K0, 9, 14);
    round!(a, b, c, d, e, f0, K0, 8, 15);

    // Round 2
    round!(e, a, b, c, d, f1, K1, 7, 7);
    round!(d, e, a, b, c, f1, K1, 6, 4);
    round!(c, d, e, a, b, f1, K1, 8, 13);
    round!(b, c, d, e, a, f1, K1, 13, 1);
    round!(a, b, c, d, e, f1, K1, 11, 10);
    round!(e, a, b, c, d, f1, K1, 9, 6);
    round!(d, e, a, b, c, f1, K1, 7, 15);
    round!(c, d, e, a, b, f1, K1, 15, 3);
    round!(b, c, d, e, a, f1, K1, 7, 12);
    round!(a, b, c, d, e, f1, K1, 12, 0);
    round!(e, a, b, c, d, f1, K1, 15, 9);
    round!(d, e, a, b, c, f1, K1, 9, 5);
    round!(c, d, e, a, b, f1, K1, 11, 2);
    round!(b, c, d, e, a, f1, K1, 7, 14);
    round!(a, b, c, d, e, f1, K1, 13, 11);
    round!(e, a, b, c, d, f1, K1, 12, 8);

    // Round 3
    round!(d, e, a, b, c, f2, K2, 11, 3);
    round!(c, d, e, a, b, f2, K2, 13, 10);
    round!(b, c, d, e, a, f2, K2, 6, 14);
    round!(a, b, c, d, e, f2, K2, 7, 4);
    round!(e, a, b, c, d, f2, K2, 14, 9);
    round!(d, e, a, b, c, f2, K2, 9, 15);
    round!(c, d, e, a, b, f2, K2, 13, 8);
    round!(b, c, d, e, a, f2, K2, 15, 1);
    round!(a, b, c, d, e, f2, K2, 14, 2);
    round!(e, a, b, c, d, f2, K2, 8, 7);
    round!(d, e, a, b, c, f2, K2, 13, 0);
    round!(c, d, e, a, b, f2, K2, 6, 6);
    round!(b, c, d, e, a, f2, K2, 5, 13);
    round!(a, b, c, d, e, f2, K2, 12, 11);
    round!(e, a, b, c, d, f2, K2, 7, 5);
    round!(d, e, a, b, c, f2, K2, 5, 12);

    // Round 4
    round!(c, d, e, a, b, f3, K3, 11, 1);
    round!(b, c, d, e, a, f3, K3, 12, 9);
    round!(a, b, c, d, e, f3, K3, 14, 11);
    round!(e, a, b, c, d, f3, K3, 15, 10);
    round!(d, e, a, b, c, f3, K3, 14, 0);
    round!(c, d, e, a, b, f3, K3, 15, 8);
    round!(b, c, d, e, a, f3, K3, 9, 12);
    round!(a, b, c, d, e, f3, K3, 8, 4);
    round!(e, a, b, c, d, f3, K3, 9, 13);
    round!(d, e, a, b, c, f3, K3, 14, 3);
    round!(c, d, e, a, b, f3, K3, 5, 7);
    round!(b, c, d, e, a, f3, K3, 6, 15);
    round!(a, b, c, d, e, f3, K3, 8, 14);
    round!(e, a, b, c, d, f3, K3, 6, 5);
    round!(d, e, a, b, c, f3, K3, 5, 6);
    round!(c, d, e, a, b, f3, K3, 12, 2);

    // Round 5
    round!(b, c, d, e, a, f4, K4, 9, 4);
    round!(a, b, c, d, e, f4, K4, 15, 0);
    round!(e, a, b, c, d, f4, K4, 5, 5);
    round!(d, e, a, b, c, f4, K4, 11, 9);
    round!(c, d, e, a, b, f4, K4, 6, 7);
    round!(b, c, d, e, a, f4, K4, 8, 12);
    round!(a, b, c, d, e, f4, K4, 13, 2);
    round!(e, a, b, c, d, f4, K4, 12, 10);
    round!(d, e, a, b, c, f4, K4, 5, 14);
    round!(c, d, e, a, b, f4, K4, 12, 1);
    round!(b, c, d, e, a, f4, K4, 13, 3);
    round!(a, b, c, d, e, f4, K4, 14, 8);
    round!(e, a, b, c, d, f4, K4, 11, 11);
    round!(d, e, a, b, c, f4, K4, 8, 6);
    round!(c, d, e, a, b, f4, K4, 5, 15);
    round!(b, c, d, e, a, f4, K4, 6, 13);

    let (aa, bb, cc, dd, ee) = (a, b, c, d, e);
    let (mut a, mut b, mut c, mut d, mut e) = (state[0], state[1], state[2], state[3], state[4]);

    // Parallel round 1
    round!(a, b, c, d, e, f4, KK0, 8, 5);
    round!(e, a, b, c, d, f4, KK0, 9, 14);
    round!(d, e, a, b, c, f4, KK0, 9, 7);
    round!(c, d, e, a, b, f4, KK0, 11, 0);
    round!(b, c, d, e, a, f4, KK0, 13, 9);
    round!(a, b, c, d, e, f4, KK0, 15, 2);
    round!(e, a, b, c, d, f4, KK0, 15, 11);
    round!(d, e, a, b, c, f4, KK0, 5, 4);
    round!(c, d, e, a, b, f4, KK0, 7, 13);
    round!(b, c, d, e, a, f4, KK0, 7, 6);
    round!(a, b, c, d, e, f4, KK0, 8, 15);
    round!(e, a, b, c, d, f4, KK0, 11, 8);
    round!(d, e, a, b, c, f4, KK0, 14, 1);
    round!(c, d, e, a, b, f4, KK0, 14, 10);
    round!(b, c, d, e, a, f4, KK0, 12, 3);
    round!(a, b, c, d, e, f4, KK0, 6, 12);

    // Parallel round 2
    round!(e, a, b, c, d, f3, KK1, 9, 6);
    round!(d, e, a, b, c, f3, KK1, 13, 11);
    round!(c, d, e, a, b, f3, KK1, 15, 3);
    round!(b, c, d, e, a, f3, KK1, 7, 7);
    round!(a, b, c, d, e, f3, KK1, 12, 0);
    round!(e, a, b, c, d, f3, KK1, 8, 13);
    round!(d, e, a, b, c, f3, KK1, 9, 5);
    round!(c, d, e, a, b, f3, KK1, 11, 10);
    round!(b, c, d, e, a, f3, KK1, 7, 14);
    round!(a, b, c, d, e, f3, KK1, 7, 15);
    round!(e, a, b, c, d, f3, KK1, 12, 8);
    round!(d, e, a, b, c, f3, KK1, 7, 12);
    round!(c, d, e, a, b, f3, KK1, 6, 4);
    round!(b, c, d, e, a, f3, KK1, 15, 9);
    round!(a, b, c, d, e, f3, KK1, 13, 1);
    round!(e, a, b, c, d, f3, KK1, 11, 2);

    // Parallel round 3
    round!(d, e, a, b, c, f2, KK2, 9, 15);
    round!(c, d, e, a, b, f2, KK2, 7, 5);
    round!(b, c, d, e, a, f2, KK2, 15, 1);
    round!(a, b, c, d, e, f2, KK2, 11, 3);
    round!(e, a, b, c, d, f2, KK2, 8, 7);
    round!(d, e, a, b, c, f2, KK2, 6, 14);
    round!(c, d, e, a, b, f2, KK2, 6, 6);
    round!(b, c, d, e, a, f2, KK2, 14, 9);
    round!(a, b, c, d, e, f2, KK2, 12, 11);
    round!(e, a, b, c, d, f2, KK2, 13, 8);
    round!(d, e, a, b, c, f2, KK2, 5, 12);
    round!(c, d, e, a, b, f2, KK2, 14, 2);
    round!(b, c, d, e, a, f2, KK2, 13, 10);
    round!(a, b, c, d, e, f2, KK2, 13, 0);
    round!(e, a, b, c, d, f2, KK2, 7, 4);
    round!(d, e, a, b, c, f2, KK2, 5, 13);

    // Parallel round 4
    round!(c, d, e, a, b, f1, KK3, 15, 8);
    round!(b, c, d, e, a, f1, KK3, 5, 6);
    round!(a, b, c, d, e, f1, KK3, 8, 4);
    round!(e, a, b, c, d, f1, KK3, 11, 1);
    round!(d, e, a, b, c, f1, KK3, 14, 3);
    round!(c, d, e, a, b, f1, KK3, 14, 11);
    round!(b, c, d, e, a, f1, KK3, 6, 15);
    round!(a, b, c, d, e, f1, KK3, 14, 0);
    round!(e, a, b, c, d, f1, KK3, 6, 5);
    round!(d, e, a, b, c, f1, KK3, 9, 12);
    round!(c, d, e, a, b, f1, KK3, 12, 2);
    round!(b, c, d, e, a, f1, KK3, 9, 13);
    round!(a, b, c, d, e, f1, KK3, 12, 9);
    round!(e, a, b, c, d, f1, KK3, 5, 7);
    round!(d, e, a, b, c, f1, KK3, 15, 10);
    round!(c, d, e, a, b, f1, KK3, 8, 14);

    // Parallel round 5
    round!(b, c, d, e, a, f0, KK4, 8, 12);
    round!(a, b, c, d, e, f0, KK4, 5, 15);
    round!(e, a, b, c, d, f0, KK4, 12, 10);
    round!(d, e, a, b, c, f0, KK4, 9, 4);
    round!(c, d, e, a, b, f0, KK4, 12, 1);
    round!(b, c, d, e, a, f0, KK4, 5, 5);
    round!(a, b, c, d, e, f0, KK4, 14, 8);
    round!(e, a, b, c, d, f0, KK4, 6, 7);
    round!(d, e, a, b, c, f0, KK4, 8, 6);
    round!(c, d, e, a, b, f0, KK4, 13, 2);
    round!(b, c, d, e, a, f0, KK4, 6, 13);
    round!(a, b, c, d, e, f0, KK4, 5, 14);
    round!(e, a, b, c, d, f0, KK4, 15, 0);
    round!(d, e, a, b, c, f0, KK4, 13, 3);
    round!(c, d, e, a, b, f0, KK4, 11, 9);
    round!(b, c, d, e, a, f0, KK4, 11, 11);

    let t = state[1].wrapping_add(cc).wrapping_add(d);
    state[1] = state[2].wrapping_add(dd).wrapping_add(e);
    state[2] = state[3].wrapping_add(ee).wrapping_add(a);
    state[3] = state[4].wrapping_add(aa).wrapping_add(b);
    state[4] = state[0].wrapping_add(bb).wrapping_add(c);
    state[0] = t;
}

#[cfg(test)]
mod tests {
    use super::ripemd160;

    #[test]
    fn test_ripemd160() {
        let repeated_str = "1234567890".repeat(8);
        let a1000 = "a".repeat(1000);
        let test_pairs = [
            ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
            ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
            (
                repeated_str.as_str(),
                "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
            ),
            // ("a".repeat(1000000).as_str(), "52783243c1697bdbe16d37f97f68f08325dc1528"), // can
            // take a while to compute
            (a1000.as_str(), "aa69deee9a8922e92f8105e007f76110f381e9cf"), /* I made this shorter
                                                                           * one up instead */
        ];

        for (input, expected) in test_pairs.iter() {
            let result = ripemd160(input.as_bytes());
            let result_hex = hex::encode(result);
            assert_eq!(expected, &result_hex);
        }
    }
}
