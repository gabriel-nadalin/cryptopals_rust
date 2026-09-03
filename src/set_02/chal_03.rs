#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s02_c03_ecb_cbc_detection_oracle() {
        let payload = b"YELLOW SUBMARINE".repeat(5);

        for _ in 0..30 {
            let (ciphertext, is_ecb) = random_encryption_oracle(&payload);
    
            let prediction = detect_ecb(&ciphertext);
    
            assert_eq!(is_ecb, prediction);
        }
    }
}