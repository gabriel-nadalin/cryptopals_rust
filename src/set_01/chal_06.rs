#[cfg(test)]
mod tests {
    use crate::core::*;
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn s01_c06_cracking_repeating_key_xor() {
        let file_in = File::open("src/set_01/chal_06.txt").unwrap();
        let mut reader_in = BufReader::new(file_in);
        let mut contents = String::new();
        reader_in.read_to_string(&mut contents).unwrap();
        
        let input = base64_to_bytes(&contents.replace("\n", ""));

        let key = crack_repeating_key_xor(&input);

        let decrypted = repeating_key_xor(&input, &key);

        let file_out = File::open("src/set_01/chal_06_decode.txt").unwrap();
        let mut reader_out = BufReader::new(file_out);
        let mut expected = Vec::new();
        reader_out.read_to_end(&mut expected).unwrap();

        assert_eq!(decrypted, expected);
    }
}