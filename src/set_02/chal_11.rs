#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::*;

    fn random_encryption_oracle(payload: &[u8]) -> (Vec<u8>, bool) {
        let prefix = rand::random_iter().take(rand::random_range(5..=10)).collect_vec();
        let suffix = rand::random_iter().take(rand::random_range(5..=10)).collect_vec();
        let concat = [&prefix, payload, &suffix].concat();

        let choice = rand::random();
        if choice {
            (ecb_encrypt(&concat, &AES_KEY), choice)
        } else {
            let iv = rand::random_iter().take(16).collect_vec();
            (cbc_encrypt(&concat, &AES_KEY, &iv), choice)
        }
    }

    #[test]
    fn s02_c11_ecb_cbc_detection_oracle() {
        let payload = b"YELLOW SUBMARINE".repeat(5);

        for _ in 0..30 {
            let (ciphertext, is_ecb) = random_encryption_oracle(&payload);
    
            let prediction = detect_ecb(&ciphertext);
    
            assert_eq!(is_ecb, prediction);
        }
    }
}