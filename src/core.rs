#![allow(dead_code)]

use std::{assert_eq, ops::Range};
use hex;
use base64::prelude::*;
use itertools::Itertools;
use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};
use once_cell::sync::Lazy;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, block_padding::{NoPadding, Pkcs7}};

pub type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
pub type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

pub const ENGLISH_FREQ: Lazy<HashMap<char, f64>> = Lazy::new(|| {
    HashMap::from([
        ('e', 12.70), ('t', 9.06), ('a', 8.17), ('o', 7.51),
        ('i', 6.97), ('n', 6.75), ('s', 6.33), ('h', 6.09),
        ('r', 5.99), ('d', 4.25), ('l', 4.03), ('c', 2.78),
        ('u', 2.76), ('m', 2.41), ('w', 2.36), ('f', 2.23),
        ('g', 2.02), ('y', 1.97), ('p', 1.93), ('b', 1.29),
        ('v', 0.98), ('k', 0.77), ('j', 0.15), ('x', 0.15),
        ('q', 0.10), ('z', 0.07), (' ', 13.00), (0 as char, 0.0)
    ])
});

pub static SECRET_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    generate_aes_key()
});

pub static SECRET_IV: Lazy<Vec<u8>> = Lazy::new(|| {
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

pub fn single_byte_xor(bytes: &[u8], key: &u8) -> Vec<u8> {
    bytes.iter().map(|byte| byte ^ key).collect()
}

pub fn score_english(bytes: &[u8]) -> f64 {
    let mut score = 0.0;

    for &byte in bytes {
        score += match byte {
            b' ' => 13.0,                       // most common char
            b'a'..=b'z' => ENGLISH_FREQ[&(byte as char)],          // lowercase, full weight
            b'A'..=b'Z' => ENGLISH_FREQ[&(byte.to_ascii_lowercase() as char)] * 0.2,
            b'\'' => 2.0,                       // contractions/possessives (poetry!)
            b'.'  => 2.5, b',' => 1.5, b'-' => 1.0, b':' => 1.0,
            b'?'  => 0.8, b'!' => 0.5, b'"' => 0.5, b';' => 0.5,
            b'0'..=b'9' => 0.5,
            _ => -10.0,                         // control / rare / high bytes
        };

    }
    score
}

pub fn crack_single_byte_xor(bytes: &[u8]) -> (u8, Vec<u8>, f64) {
    (0..=255)
        .map(|key| {
            let plaintext = single_byte_xor(bytes, &key);
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
    let keysize = (2..=128)
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
        .filter(|(_keysize, avg)| !avg.is_nan())
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

pub fn pkcs7_pad(plaintext: &[u8], block_size: usize) -> Vec<u8> {
    let last_block = plaintext.chunks(block_size).last().unwrap();
    let mut n = block_size - last_block.len();
    if n == 0 { n = block_size };
    let padding = vec![n as u8; n];
    [plaintext, &padding].concat()
}

pub fn pkcs7_unpad(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let n = plaintext.last().unwrap();
    let pad = &plaintext[plaintext.len().saturating_sub(*n as usize)..];

    if *n > 16 || *n == 0 || pad.iter().any(|x| x != n) {
        Err("invalid padding".to_owned())
    } else {
        Ok(plaintext[..plaintext.len().saturating_sub(*n as usize)].to_vec())
    }
}

pub fn ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    Aes128EcbDec::new_from_slice(key)
        .unwrap()
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|e| e.to_string())
}

pub fn ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    Aes128EcbEnc::new_from_slice(key)
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(&plaintext)
}

pub fn detect_ecb(ciphertext: &[u8]) -> bool {
    let counts: Vec<(Vec<u8>, usize)> = ciphertext.chunks(16)
        .counts()
        .iter()
        .sorted_by(|a, b| b.1.partial_cmp(&a.1).unwrap())
        .map(|(a, b)| (a.to_vec(), *b))
        .collect();

    counts[0].1 > 1
}

pub fn cbc_decrypt(ciphertext: &[u8], key: &[u8], iv:&[u8]) -> Result<Vec<u8>, String> {
    let block_size = key.len();
    let mut blocks = ciphertext.chunks(block_size).collect_vec();
    blocks.insert(0, iv);

    let plaintext: Vec<u8> = blocks
        .iter()
        .tuple_windows()
        .map(|(prev_block, cur_block)| {
            let decrypted = Aes128EcbDec::new_from_slice(key)
                .unwrap()
                .decrypt_padded_vec::<NoPadding>(cur_block)
                .unwrap();

            xor_slice(&decrypted, prev_block)
        })
        .flatten()
        .collect();

    pkcs7_unpad(&plaintext)
}

pub fn cbc_encrypt(plaintext: &[u8], key: &[u8], iv:&[u8]) -> Vec<u8> {
    let block_size = key.len();
    let padded = pkcs7_pad(plaintext, block_size);
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

pub fn kv_to_hashmap(string: &str) -> HashMap<String, String> {
    string.split('&')
        .map(|items| {
            let item = items.split('=').collect_vec();
            (item[0].to_string(), item[1].to_string())
        })
        .collect()
}

pub fn hashmap_to_kv(hashmap: HashMap<String, String>) -> String {
    hashmap.iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .join("&")
}

pub fn detect_prefix_len<F>(encrypt_fn: F, block_size: usize) -> usize where F: Fn(&[u8]) -> Vec<u8> {
    for i in 0..3*block_size {
        let payload = vec!['A' as u8; i];
        let ciphertext = encrypt_fn(&payload);
        if detect_ecb(&ciphertext) {
            return (block_size - (i % block_size)) % block_size;
        }
    }
    0
}

pub fn ctr(input: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    input.chunks(16)
        .enumerate()
        .map(|(i, block)| {
            let keystream = Aes128EcbEnc::new_from_slice(key)
                .unwrap()
                .encrypt_padded_vec::<NoPadding>(&&[nonce.to_le_bytes(), i.to_le_bytes()].concat());
            xor_slice(block, &keystream[..block.len()])
        })
        .flatten()
        .collect()
}

pub fn unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

pub struct MT19937 {
    state_array: Vec<u32>,
    index: usize
}

impl MT19937 {
    pub const N: usize = 624;
    pub const M: usize = 397;
    pub const W: u32 = 32;
    pub const R: u32 = 31;
    pub const UMASK: u32 = (0xffffffff << Self::R);
    pub const LMASK: u32 = (0xffffffff >> (Self::W - Self::R));
    pub const A: u32 = 0x9908b0df;
    pub const U: u32 = 11;
    pub const S: u32 = 7;
    pub const T: u32 = 15;
    pub const L: u32 = 18;
    pub const B: u32 = 0x9d2c5680;
    pub const C: u32 = 0xefc60000;
    pub const F: u32 = 1812433253;

    pub fn new(seed: &u32) -> Self {
        let mut seed = seed.clone();
        let mut state_array = vec![seed];

        for i in 1..Self::N as u32 {
            seed = Self::F.wrapping_mul(seed ^ (seed >> (Self::W-2))).wrapping_add(i);
            state_array.push(seed);
        }

        Self {
            state_array,
            index: 0
        }
    }

    pub fn random_u32(&mut self) -> u32 {
        let mut k = self.index;
        let mut j = (k + 1) % Self::N;

        let mut x = (self.state_array[k] & Self::UMASK) | (self.state_array[j] & Self::LMASK);
        let mut x_a = x >> 1;
        if x & 1 == 1 { x_a ^= Self::A };

        j = (k + Self::M) % Self::N;

        x = self.state_array[j] ^ x_a;
        self.state_array[k] = x;
        k += 1;

        if k >= Self::N { k = 0 };
        self.index = k;

        let mut y = x ^ (x >> Self::U);         // tempering
        y = y ^ ((y << Self::S) & Self::B);
        y = y ^ ((y << Self::T) & Self::C);
        let z = y ^ (y >> Self::L);

        z
    }

    pub fn new_from_vec(state_array: Vec<u32>) -> Self {
        Self {
            state_array,
            index: 0,
        }
    }
}

// turn MT19937 into a stream cipher. same function for encrypting and decrypting
pub fn mt19937_stream_cipher(input: &[u8], seed: &u32) -> Vec<u8> {
    let mut rng = MT19937::new(&seed);
    input.chunks(4)
        .map(|block| xor_slice(block, &rng.random_u32().to_be_bytes()[..block.len()]))
        .flatten()
        .collect()
}

pub fn crack_mt19937(bytes: &[u8], mut range: Range<u32>) -> Option<u32> {
    range.find(|seed| {
        let mut rng = MT19937::new(seed);
        let candidate = bytes.chunks(4)
            .map(|_| rng.random_u32().to_be_bytes())
            .flatten()
            .collect_vec();

        candidate == bytes
    })
}