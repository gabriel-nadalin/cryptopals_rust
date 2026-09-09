#[cfg(test)]
mod tests {
    use crate::core::*;

    fn edit(ciphertext: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
        let mut decrypted = ctr(ciphertext, &AES_KEY, *NONCE);
        decrypted.splice(offset..offset + newtext.len(), newtext.to_owned());
        ctr(&decrypted, &AES_KEY, *NONCE)
    }

    fn encrypt_file() -> Vec<u8> {
        let input = base64_to_bytes(&file_to_string("src/set_04/chal_25.txt"));
        let ecb_key = b"YELLOW SUBMARINE";
        let dec_from_ecb = ecb_decrypt(&input, ecb_key).unwrap();

        ctr(&dec_from_ecb, &AES_KEY, *NONCE)
    }

    #[test]
    fn s04_c25_random_access_aes_ctr() {
        let ciphertext = encrypt_file();

        let payload = vec![0; ciphertext.len()];
        let keystream = edit(&ciphertext,0, &payload);
        let recovered = xor_slice(&ciphertext, &keystream);
        
        let expected = file_to_bytes("src/set_04/chal_25_decode.txt");

        assert_eq!(recovered, expected);
    }
}