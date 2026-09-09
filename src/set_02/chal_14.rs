#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use crate::core::*;

    static SECRET_PREFIX: Lazy<Vec<u8>> = Lazy::new(|| {
        rand::random_iter().take(rand::random_range(0..16)).collect()
    });

    fn encrypt_prefix_suffix(payload: &[u8]) -> Vec<u8> {
        let suffix = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        
        let plaintext = [&SECRET_PREFIX, payload, &suffix].concat();

        ecb_encrypt(&plaintext, &AES_KEY)
    }

    #[test]
    fn s02_c14_byte_at_a_time_ecb_decryption_hard() {
        let block_size = detect_block_size(encrypt_prefix_suffix);

        let is_ecb = detect_ecb(&encrypt_prefix_suffix(&['A' as u8; 64]));
        assert_eq!(is_ecb, true);

        let prefix_len = detect_prefix_len(encrypt_prefix_suffix, block_size);

        let mut plaintext = Vec::new();
        for (i, block) in encrypt_prefix_suffix(&[]).chunks(block_size).enumerate() {
            let mut prefix = [vec!['A' as u8; 2*block_size - prefix_len - 1]].concat();

            for _ in block {
                let baseline = encrypt_prefix_suffix(&prefix);

                for byte in 0..=255 {
                    let payload = [prefix.clone(), plaintext.clone(), vec![byte]].concat();
                    let ciphertext = encrypt_prefix_suffix(&payload);
                    
                    if ciphertext[..(i+2) * block_size] == baseline[..(i+2) * block_size] {
                        plaintext.push(byte);
                        prefix.pop();
                        break;
                    }
                }
            }
        }

        plaintext = pkcs7_unpad(&plaintext).unwrap();
        let expected = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        
        assert_eq!(plaintext, expected);
    }
}