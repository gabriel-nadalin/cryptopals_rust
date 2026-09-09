#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s02_c10_implement_cbc_mode() {
        let ciphertext = base64_to_bytes(&file_to_string("src/set_02/chal_10.txt"));

        let key = b"YELLOW SUBMARINE";
        let iv = vec![0; key.len()];

        let decrypted = cbc_decrypt(&ciphertext, key, &iv).unwrap();
        
        let expected = file_to_bytes("src/set_02/chal_10_decode.txt");

        assert_eq!(decrypted, expected);
    }
}