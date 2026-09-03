#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s02_c04_byte_at_a_time_ecb_decryption() {
        let block_size = detect_block_size(encrypt_append);

        let is_ecb = detect_ecb(&encrypt_append(&['A' as u8; 64]));
        assert_eq!(is_ecb, true);

        let mut plaintext = Vec::new();
        for (i, block) in encrypt_append(&[]).chunks(block_size).enumerate() {
            let mut prefix = [vec!['A' as u8; block_size - 1]].concat();

            for _ in block {
                let baseline = encrypt_append(&prefix);

                for byte in 0..=255 {
                    let payload = [prefix.clone(), plaintext.clone(), vec![byte]].concat();
                    let ciphertext = encrypt_append(&payload);
                    
                    if ciphertext[..(i+1) * block_size] == baseline[..(i+1) * block_size] {
                        plaintext.push(byte);
                        prefix.pop();
                        break;
                    }
                }
            }
        }

        plaintext = pkcs7_unpad(&plaintext);
        let expected = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
        
        assert_eq!(plaintext, expected);
    }
}