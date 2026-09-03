#![allow(dead_code)]

use std::assert_eq;
use hex;
use base64::prelude::*;
use itertools::Itertools;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, block_padding::NoPadding};

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

pub const ENGLISH_FREQ: Lazy<HashMap<char, f64>> = Lazy::new(|| {
    HashMap::from([
        ('e', 12.70), ('t', 9.06), ('a', 8.17), ('o', 7.51),
        ('i', 6.97), ('n', 6.75), ('s', 6.33), ('h', 6.09),
        ('r', 5.99), ('d', 4.25), ('l', 4.03), ('c', 2.78),
        ('u', 2.76), ('m', 2.41), ('w', 2.36), ('f', 2.23),
        ('g', 2.02), ('y', 1.97), ('p', 1.93), ('b', 1.29),
        ('v', 0.98), ('k', 0.77), ('j', 0.15), ('x', 0.15),
        ('q', 0.10), ('z', 0.07), (' ', 13.00)
    ])
});

// key for challenge s02c03
pub static SECRET_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    generate_aes_key()
});

pub fn hex_to_bytes(string: &str) -> Vec<u8> {
    hex::decode(string).unwrap()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn base64_to_bytes(string: &str) -> Vec<u8> {
    BASE64_STANDARD.decode(string).unwrap()
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

pub fn bytes_to_ascii(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

pub fn xor_slice(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .map(|(byte_a, byte_b)| byte_a ^ byte_b)
        .collect()
}

pub fn single_byte_xor(bytes: &[u8], key: u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ key).collect()
}

pub fn score_english(bytes: &[u8]) -> f64 {
    let mut score = 0.0;

    for byte in bytes {
        let chr = byte.to_ascii_lowercase() as char;
        if ENGLISH_FREQ.contains_key(&chr) {
            score += ENGLISH_FREQ[&chr]
        } 
        else {
            score -= 10.0
        }
    }

    score
}

pub fn crack_single_byte_xor(bytes: &[u8]) -> (u8, Vec<u8>, f64) {
    (0..=255)
        .map(|key| {
            let plaintext = single_byte_xor(bytes, key);
            let score = score_english(&plaintext);
            (key, plaintext, score)
        })
        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap())
        .unwrap()
}

pub fn repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let size = plaintext.len();
    let mut key_vec = Vec::with_capacity(size);
    key_vec.extend(key.iter().cloned().cycle().take(size));

    xor_slice(plaintext, &key_vec)
}

pub fn hamming_distance_byte(a: u8, b: u8) -> usize {
    let mut distance = 0;
    let mut xor = a ^ b;
    for _ in 0..8 {
        if xor & 1 == 1 {
            distance += 1;
        }
        xor >>= 1;
    }
    distance
}

pub fn hamming_distance_slice(a: &[u8], b: &[u8]) -> usize {
    assert_eq!(a.len(), b.len());

    a.iter()
        .zip(b.iter())
        .map(|(byte_a, byte_b)| hamming_distance_byte(*byte_a, *byte_b))
        .sum()
}

pub fn crack_repeating_key_xor(ciphertext: &[u8]) -> Vec<u8> {
    let keysize = (2..=40)
        .map(|keysize| {
            let mut total = 0.0;
            let mut count = 0;

            for i in 0..ciphertext.len() / (2 * keysize) {
                let a = &ciphertext[i * keysize .. (i + 1) * keysize];
                let b = &ciphertext[(i + 1) * keysize .. (i + 2) * keysize];
                total += hamming_distance_slice(a, b) as f64 / keysize as f64;
                count += 1;
            }
            let avg = total / count as f64;
    
            (keysize, avg)
        })
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(keysize, _avg)| keysize)
        .unwrap();

    let mut key = Vec::new();
    for i in 0..keysize {
        let block: Vec<_> = ciphertext.iter().cloned().skip(i).step_by(keysize).collect();
        let (key_byte, _plaintext, _score) = crack_single_byte_xor(&block);
        key.push(key_byte);
    }

    key
}

pub fn pkcs7_pad(payload: &[u8], block_size: usize) -> Vec<u8> {
    let last_block = payload.chunks(block_size).last().unwrap();
    let mut n = block_size - last_block.len();
    if n == 0 { n = block_size };
    let padding = vec![n as u8; n];
    [payload, &padding].concat()
}

pub fn pkcs7_unpad(payload: &[u8]) -> Vec<u8> {
    let n = payload.last().unwrap();
    let pad = &payload[payload.len() - *n as usize..];

    if pad.iter().any(|x| x != n) {
        payload.to_vec()
    } else {
        payload[..payload.len() - *n as usize].to_vec()
    }
}

pub fn ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    Aes128EcbDec::new_from_slice(key)
        .unwrap()
        .decrypt_padded_vec::<NoPadding>(ciphertext)
        .unwrap()
}

pub fn ecb_encrypt(payload: &[u8], key: &[u8]) -> Vec<u8> {
    let padded = pkcs7_pad(&payload, key.len());
    Aes128EcbEnc::new_from_slice(key)
        .unwrap()
        .encrypt_padded_vec::<NoPadding>(&padded)
}

pub fn detect_ecb(ciphertext: &[u8]) -> bool {
    let counts: Vec<(Vec<u8>, usize)> = ciphertext.chunks(16)
        .counts()
        .iter()
        .sorted_by(|a, b| b.1.partial_cmp(&a.1).unwrap())
        .map(|(a, b)| (a.to_vec(), *b))
        .collect();

    counts[0].1 > 2
}

pub fn cbc_decrypt(ciphertext: &[u8], iv:&[u8], key: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    let mut blocks = ciphertext.chunks(block_size).rev().collect_vec();
    blocks.push(iv);

    let plaintext = blocks
        .windows(2)
        .map(|pair| {
            let (cur_block, next_block) = (pair[0], pair[1]);
            let decrypted = ecb_decrypt(cur_block, key);

            xor_slice(&decrypted, next_block)
        })
        .rev()
        .flatten()
        .collect();

    plaintext
}

pub fn cbc_encrypt(payload: &[u8], iv:&[u8], key: &[u8]) -> Vec<u8> {
    let block_size = key.len();
    let padded = pkcs7_pad(payload, block_size);
    let blocks = padded.chunks(block_size).collect_vec();    
    let mut prev_block = iv;
    
    let mut ciphertext = Vec::new();
    for block in blocks {
        let xor = xor_slice(&prev_block, block);
        let cipherblock = Aes128EcbEnc::new_from_slice(key)
            .unwrap()
            .encrypt_padded_vec::<NoPadding>(&xor);

        ciphertext.push(cipherblock);
        prev_block = ciphertext.last().unwrap();
    }

    ciphertext.iter().cloned().flatten().collect()
}

pub fn generate_aes_key() -> Vec<u8> {
    rand::random_iter().take(16).collect()
}

pub fn random_encryption_oracle(payload: &[u8]) -> (Vec<u8>, bool) {
    let key = generate_aes_key();
    let prefix = rand::random_iter().take(rand::random_range(5..=10)).collect_vec();
    let suffix = rand::random_iter().take(rand::random_range(5..=10)).collect_vec();
    let concat = [&prefix, payload, &suffix].concat();

    let choice = rand::random();
    if choice {
        (ecb_encrypt(&concat, &key), choice)
    } else {
        let iv = rand::random_iter().take(16).collect_vec();
        (cbc_encrypt(&concat, &iv, &key), choice)
    }
}

pub fn encrypt_append(payload: &[u8]) -> Vec<u8> {
    let suffix = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    
    let append = [payload, &suffix].concat();

    ecb_encrypt(&append, &SECRET_KEY)
}

pub fn detect_block_size<F>(encrypt_fn: F) -> usize where F: Fn(&[u8]) -> Vec<u8> {
    let base_len = encrypt_fn(&[]).len();
    for i in 0..=64 {
        let payload = vec!['A' as u8; i];
        let ciphertext = encrypt_fn(&payload);
        let len = ciphertext.len();

        if len > base_len {
            return len - base_len;
        }
    }
    panic!("could not detect block size");
}

pub fn kv_to_hashmap(string: &str) -> HashMap<Vec<u8>, Vec<u8>> {
    let x = string
        .split('&')
        .map(|kv| {
            kv.split('=').map(|[k, v]| )
        }).
}