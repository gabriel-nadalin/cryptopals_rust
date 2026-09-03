#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    use crate::core::*;

    #[test]
    fn s01_c08_detecting_aes_in_ecb_mode() {
        let file = File::open("src/set_01/chal_08.txt").unwrap();
        let reader = BufReader::new(file);

        let mut detected_row = 0;

        for (row, line) in reader.lines().enumerate() {
            let bytes = hex_to_bytes(&line.unwrap());
            if detect_ecb(&bytes) { detected_row = row }
        }

        let expected = 132;

        assert_eq!(detected_row, expected);
    }
}