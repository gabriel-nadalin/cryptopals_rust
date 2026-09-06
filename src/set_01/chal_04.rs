#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    use crate::core::*;

    #[test]
    fn s01_c04_detecting_single_byte_xor() {
        let file = File::open("src/set_01/chal_04.txt").unwrap();
        let reader = BufReader::new(file);
        let mut scores = HashMap::new();

        for (row, line) in reader.lines().enumerate() {
            let input = hex_to_bytes(&line.unwrap());
            let (key, plaintext, score) = crack_single_byte_xor(&input);
            scores.insert(row, (key, plaintext, score));
        }

        // Sort and display top results
        let mut sorted: Vec<_> = scores.iter().collect();
        sorted.sort_by(|a, b| b.1.2.partial_cmp(&a.1.2).unwrap());

        // println!("top 3 candidates\n");
        // for (row, (key, plaintext, score)) in sorted.iter().take(3) {
        //     let plain_str = String::from_utf8(plaintext.clone()).unwrap();
        //     println!("row: {}\nkey: {:02x} ({})\nplaintext: {}\nscore: {:.2}\n", row, key, key, plain_str, score);
        // }

        let result = &sorted.first().unwrap().1.1;
        let expected = "Now that the party is jumping\n".as_bytes();

        assert_eq!(result, expected);
    }
}