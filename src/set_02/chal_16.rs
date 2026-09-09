#[cfg(test)]
mod tests {
    use crate::core::*;

    fn encrypt_comments(infix: &str) -> Vec<u8> {
        let infix = infix.replace(";", "").replace("=", "");
        let string = format!("comment1=cooking%20MCs;userdata={infix};comment2=%20like%20a%20pound%20of%20bacon");
        cbc_encrypt(string.as_bytes(), &AES_KEY, &IV)
    }

    fn check_admin(ciphertext: &[u8]) -> bool {
        let plaintext = cbc_decrypt(ciphertext, &AES_KEY, &IV).unwrap();
        let string = bytes_to_ascii(&plaintext);
        string.contains(";admin=true;")
    }

    #[test]
    fn s02_c16_cbc_bit_flipping_attack() {
        let payload = "a:admin<true";

        // "comment1=cooking%20MCs;userdata=a:admin<true;comment2=%20like%20a%20pound%20of%20bacon"
        // encrypted data string             ^     ^    <-we have to change these bytes
        let mut ciphertext = encrypt_comments(payload);
        ciphertext[33 - 16] ^= 1;               // -16 because in cbc bitflips only affect the next block
        ciphertext[39 - 16] ^= 1;

        assert!(check_admin(&ciphertext));
    }
}