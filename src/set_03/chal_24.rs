#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::*;

    fn encrypt_prefix(plaintext: &[u8], seed: u32) -> Vec<u8> {
        let prefix = rand::random_iter().take(rand::random_range(5..25)).collect_vec();
        mt19937_stream_cipher(&[&prefix, plaintext].concat(), seed)
    }

    fn generate_password_token() -> Vec<u8> {
        let seed = unix_time();
        let mut rng = MT19937::new(seed);
        (0..4).map(|_| rng.random_u32().to_be_bytes()).flatten().collect()
    }

    #[test]
    fn s03_c24_creating_and_cracking_mt19937_stream_cipher() {
        let plaintext = b"AAAAAAAAAAAAAA";
        let seed = rand::random::<u16>() as u32;
        let ciphertext = encrypt_prefix(plaintext, seed);

        let recovered_seed = (0..0xffff_u32)
            .find(|&seed| {
                let dec = mt19937_stream_cipher(&ciphertext, seed);
                dec[dec.len() - 14..] == *plaintext
            })
            .unwrap();

        assert_eq!(recovered_seed, seed);
        
        let token = generate_password_token();
        let now = unix_time();
        let recovered_seed = crack_mt19937(&token, now - 30 * 60..now + 1);

        assert!(recovered_seed.is_some());
    }
}