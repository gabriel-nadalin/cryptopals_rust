#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use itertools::Itertools;

    use crate::core::*;

    fn profile_for(email: &str) -> Vec<u8> {
        let email = email.replace("&", "").replace("=", "");
        let string = format!("email={email}&uid=10&role=user");
        ecb_encrypt(string.as_bytes(), &AES_KEY)
    }

    fn decrypt_profile(ciphertext: &[u8]) -> HashMap<String, String> {
        let string = bytes_to_ascii(&ecb_decrypt(ciphertext, &AES_KEY).unwrap());
        kv_to_hashmap(&string)
    }

    #[test]
    fn s02_c13_ecb_cut_and_paste() {let payload = "AAAAAAAAAA".to_owned() + &String::from_utf8(pkcs7_pad(b"admin", 16)).unwrap();
        let ciphertext = profile_for(&payload);
        let admin_block = ciphertext.chunks(16).collect_vec()[1];

        let payload = "AAAAAAAAAAAAA";
        let ciphertext = profile_for(payload);
        let mut blocks = ciphertext.chunks(16).collect_vec();

        blocks.pop();
        blocks.push(admin_block);
        let admin_account_string = blocks.concat();
        let admin_account = decrypt_profile(&admin_account_string);

        assert_eq!(admin_account.get("role").unwrap(), "admin");
    }
}