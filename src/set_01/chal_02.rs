#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn s01_c02_fixed_xor() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c");
        let b = hex_to_bytes("686974207468652062756c6c277320657965");
        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");

        let result = xor_slice(&a, &b);

        assert_eq!(result, expected);
    }
}