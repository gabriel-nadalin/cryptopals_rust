#[cfg(test)]
mod tests {
    use once_cell::sync::Lazy;

    use crate::core::*;

    static IV: Lazy<Vec<u8>> = Lazy::new(|| {
        generate_aes_key()
    });

    fn encrypt_comments(infix: &str) -> Vec<u8> {
        let infix = infix.replace(";", "").replace("=", "");
        let string = format!("comment1=cooking%20MCs;userdata={infix};comment2=%20like%20a%20pound%20of%20bacon");
        cbc_encrypt(string.as_bytes(), &IV, &SECRET_KEY)
    }

    fn check_admin(ciphertext: &[u8]) -> bool {
        let plaintext = cbc_decrypt(ciphertext, &IV, &SECRET_KEY);
        let string = bytes_to_ascii(&plaintext);
        println!("{string}");
        string.contains(";admin=true;")
    }

    #[test]
    fn s02_c08_cbc_bit_flipping_attack() {
        let payload = "a:admin<true";

        // "comment1=cooking%20MCs;userdata=a:admin<true;comment2=%20like%20a%20pound%20of%20bacon"
        // encrypted data string             ^     ^    <-we have to change these bytes
        let mut ciphertext = encrypt_comments(payload);
        ciphertext[33 - 16] ^= 1;
        ciphertext[39 - 16] ^= 1;

        assert!(check_admin(&ciphertext));
    }
}