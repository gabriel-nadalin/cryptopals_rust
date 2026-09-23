#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::*;

    fn sign_message(message: &[u8]) -> Vec<u8> {
        MD4::digest(&[&DICT_KEY, message].concat())
    }

    fn verify_message(message: &[u8], mac: &[u8]) -> bool {
        let digest = MD4::digest(&[&DICT_KEY, message].concat());
        mac == &digest
    }
    
    #[test]
    fn s04_c30_breaking_md4_keyed_mac_with_length_extension() {
        let message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let mac = sign_message(message);

        let state = mac.chunks(4).map(|chunk| u32::from_le_bytes(*chunk.as_array().unwrap())).collect_vec();

        let (forged_message, forged_mac) = (0..64)
            .map(|key_len: u64| {
                let ml = key_len + message.len() as u64;
                let padding = MD4::padding(ml);
                let forged_message = [message.as_slice(), &padding, b";admin=true"].concat();
                let mut spliced_hasher = MD4::from_slice(&state, ml + padding.len() as u64);
                spliced_hasher.update(b";admin=true");
                let forged_mac = spliced_hasher.finalize();
                (forged_message, forged_mac)
            })
            .find(|(message, mac)| verify_message(message, &mac))
            .unwrap();

        assert!(forged_message.windows(11).any(|window| window == b";admin=true"));
        assert!(verify_message(&forged_message, &forged_mac));
    }
}