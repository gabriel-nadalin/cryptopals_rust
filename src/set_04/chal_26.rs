#[cfg(test)]
mod tests {
    use crate::core::*;

    fn encrypt_comments(infix: &str) -> Vec<u8> {
        let infix = infix.replace(";", "").replace("=", "");
        let string = format!("comment1=cooking%20MCs;userdata={infix};comment2=%20like%20a%20pound%20of%20bacon");
        ctr(string.as_bytes(), &AES_KEY, *NONCE)
    }

    fn check_admin(ciphertext: &[u8]) -> bool {
        let plaintext = ctr(ciphertext, &AES_KEY, *NONCE);
        let string = bytes_to_ascii(&plaintext);
        string.contains(";admin=true;")
    }

    #[test]
    fn s04_c26_ctr_bitflipping() {
        let payload = "a:admin<true";

        // "comment1=cooking%20MCs;userdata=a:admin<true;comment2=%20like%20a%20pound%20of%20bacon"
        // encrypted data string             ^     ^    <-we have to change these bytes
        let mut ciphertext = encrypt_comments(payload);
        ciphertext[33] ^= 1;               // no -16 because in ctr bitflips only affect the current block
        ciphertext[39] ^= 1;

        assert!(check_admin(&ciphertext));
    }
}