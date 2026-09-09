#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader, Read};
    use itertools::Itertools;
    use aes::cipher::{BlockModeEncrypt, KeyInit, block_padding::NoPadding};

    use crate::core::*;

    fn encrypt_strings() -> Vec<Vec<u8>> {
        let file_in = File::open("src/set_03/chal_20.txt").unwrap();
        let mut reader_in = BufReader::new(file_in);
        let mut contents = String::new();
        reader_in.read_to_string(&mut contents).unwrap();
        
        let ciphertexts = contents.split("\n").collect_vec();
        ciphertexts.iter().map(|ciphertext| ctr(&base64_to_bytes(*ciphertext), &AES_KEY, 0)).collect_vec()
    }

    #[test]
    fn s03_c20_breaking_fixed_nonce_ctr_statistically() {
        let mut ciphertexts = encrypt_strings();

        let min_len = ciphertexts.iter().map(Vec::len).min().unwrap_or(0);
        for ciphertext in &mut ciphertexts {
            ciphertext.truncate(min_len);
        };

        let ciphertexts_concat = ciphertexts.iter().flatten().copied().collect_vec();

        let keystream = crack_repeating_key_xor(&ciphertexts_concat);

        for ciphertext in ciphertexts {
            let ciphertext = ciphertext[..keystream.len()].to_vec();
            let plaintext = xor_slice(&ciphertext, &keystream);
            println!("{}", bytes_to_ascii(&plaintext))
        }
        
        let expected_keystream = (0..10).map(|i: u64| {
            Aes128EcbEnc::new_from_slice(&AES_KEY)
                .unwrap()
                .encrypt_padded_vec::<NoPadding>(&&[0_u64.to_le_bytes(), i.to_le_bytes()].concat())
            })
            .flatten()
            .collect_vec();

        assert_eq!(keystream[1..min_len], expected_keystream[1..min_len]);
    }
}