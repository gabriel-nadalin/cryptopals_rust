#[cfg(test)]
mod tests {
    use crate::core::*;
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn s01_c07_aes_in_ecb_mode() {
        let input = base64_to_bytes(&file_to_string("src/set_01/chal_07.txt"));
        let key = b"YELLOW SUBMARINE";

        let decrypted = ecb_decrypt(&input, key).unwrap();

        let file_out = File::open("src/set_01/chal_07_decode.txt").unwrap();
        let mut reader_out = BufReader::new(file_out);
        let mut expected = Vec::new();
        reader_out.read_to_end(&mut expected).unwrap();

        assert_eq!(decrypted, expected);
    }
}