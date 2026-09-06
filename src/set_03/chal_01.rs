#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::*;

    const STRINGS: [&str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    fn random_encrypt() -> (Vec<u8>, Vec<u8>) {
        let string = STRINGS[rand::random_range(0..10)];
        let ciphertext = cbc_encrypt(&base64_to_bytes(string), &SECRET_KEY, &SECRET_IV);
        (ciphertext, SECRET_IV.to_vec())
    }

    fn padding_is_valid(ciphertext: &[u8], iv: &[u8]) -> bool {
        let plaintext = cbc_decrypt(ciphertext, &SECRET_KEY, iv);

        match plaintext {
            Ok(_) => true,
            Err(_) => false            
        }
    }

    #[test]
    fn s03_c01_the_cbc_padding_oracle() {
        let (ciphertext, iv) = random_encrypt();
        let mut plaintext = Vec::new();

        for (prev_block, cur_block) in [iv, ciphertext].concat().chunks(16).tuple_windows() {
            let mut plainblock = vec![0; 16];
            let mut interblock = vec![0; 16];
            let mut payload = prev_block.to_vec();

            for i in 0..16 {

                for candidate in 0..=255 {

                    payload[15 - i] = candidate;
                    if padding_is_valid(&cur_block, &payload) {
                    if i == 0 {
                        let mut copy = payload.to_vec();
                        copy[14] ^= 1;
                        if !padding_is_valid(&cur_block, &copy) {
                            continue
                        }
                    }
                    interblock[15-i] = candidate ^ (i + 1) as u8;
                    plainblock[15-i] = prev_block[15-i] ^ interblock[15-i];
                    for j in 15-i..16 {
                        payload[j] = (i+2) as u8 ^ interblock[j];
                    }
                    break;
                    }
                }
            }
            plaintext.append(&mut plainblock);
        }
        let plaintext = pkcs7_unpad(&plaintext).unwrap();

        assert!(STRINGS.iter().any(|s| base64_to_bytes(s) == plaintext.as_slice()));
    }
}