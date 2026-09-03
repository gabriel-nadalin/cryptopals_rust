#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s02_c01_implement_pkcs7_padding() {
        let payload = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";

        let result = pkcs7_pad(payload, 20);
        
        assert_eq!(result, expected);
    }
}