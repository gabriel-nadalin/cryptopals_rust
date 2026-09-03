#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s01_c01_hex_to_base64() {
        let input = hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let result = bytes_to_base64(&input);
        
        assert_eq!(result, expected);
    }
}