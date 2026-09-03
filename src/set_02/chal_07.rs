#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s02_c07_pkcs7_padding_validation() {
        assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04"), Ok(b"ICE ICE BABY".to_vec()));
        assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05"), Err("invalid padding".to_owned()));
        assert_eq!(pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04"), Err("invalid padding".to_owned()));
    }
}