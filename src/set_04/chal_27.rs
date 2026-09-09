#[cfg(test)]
mod tests {
    use crate::core::*;

    fn encrypt_message() -> Vec<u8> {
        let string = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
        cbc_encrypt(string, &AES_KEY, &AES_KEY)
    }

    fn check_message(ciphertext: &[u8]) -> Result<(), Vec<u8>> {
        let plaintext = cbc_decrypt(ciphertext, &AES_KEY, &AES_KEY).unwrap();
        let string = bytes_to_ascii(&plaintext);
        if string.is_ascii() {
            Ok(())
        } else {
            Err(plaintext)
        }
    }

    #[test]
    fn s04_c27_recovering_key_from_cbc_with_iv_key() {
        let key;
        let mut message = encrypt_message();
        message.splice(16..32, [0; 16]);
        message.splice(32..48, message[0..16].to_vec());

        let result = check_message(&message);
        match result {
            Ok(_) => panic!(),
            Err(plaintext) => {
                key = xor_slice(&plaintext[0..16], &plaintext[32..48]);
            }
        }
        assert_eq!(key, *AES_KEY);
    }
}