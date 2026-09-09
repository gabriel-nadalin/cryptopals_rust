#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s03_c18_implementing_ctr() {
        let string = base64_to_bytes("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
        let key = b"YELLOW SUBMARINE";
        let nonce = 0;
        let decrypted = ctr(&string, key, nonce);
        assert_eq!(decrypted, b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")
    }
}