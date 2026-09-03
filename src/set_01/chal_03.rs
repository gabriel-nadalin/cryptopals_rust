#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s01_c03_single_byte_xor() {
        let input = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
        let (key, plaintext, score) = crack_single_byte_xor(&input);
        
        let plain_str = String::from_utf8(plaintext.clone()).unwrap();
        println!("key: {:02x} ({})\nplaintext: {}\nscore: {:.2}\n", key, key, plain_str, score);

        let expected = "Cooking MC's like a pound of bacon".as_bytes();

        assert_eq!(plaintext, expected);
    }
}