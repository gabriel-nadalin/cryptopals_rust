#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use crate::core::*;

    const TEST_VEC: Lazy<[(Vec<u8>, Vec<u8>); 5]> = Lazy::new(|| {
        [
            (b"abc".to_vec(), hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d")),
            (b"".to_vec(), hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709")),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(), hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1")),
            (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec(), hex_to_bytes("a49b2446a02c645bf419f995b67091253a04a259")),
            (b"a".repeat(1_000_000).to_vec(), hex_to_bytes("34aa973cd4c4daa4f61eeb2bdbad27316534016f")),
        ]
    });

    #[test]
    fn s04_c28_implementing_sha1() {
        for (message, expected) in &*TEST_VEC {
            let hash = SHA1::digest(message);
            assert_eq!(hash, *expected);
        }
    }
}