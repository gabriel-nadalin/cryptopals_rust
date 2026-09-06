#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufReader, Read};

    use crate::core::*;

    #[test]
    fn s02_c02_implement_cbc_mode() {
        let file_in = File::open("src/set_02/chal_02.txt").unwrap();
        let mut reader_in = BufReader::new(file_in);
        let mut contents = String::new();
        reader_in.read_to_string(&mut contents).unwrap();
        
        let ciphertext = base64_to_bytes(&contents.replace("\n", ""));

        let key = b"YELLOW SUBMARINE";
        let iv = vec![0; key.len()];

        let decrypted = cbc_decrypt(&ciphertext, key, &iv).unwrap();
        
        let file_out = File::open("src/set_02/chal_02_decode.txt").unwrap();
        let mut reader_out = BufReader::new(file_out);
        let mut expected = Vec::new();
        reader_out.read_to_end(&mut expected).unwrap();

        assert_eq!(decrypted, expected);
    }
}