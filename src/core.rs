#![allow(dead_code)]

use std::{assert_eq, ops::Range, fs};
use hex;
use base64::prelude::*;
use itertools::Itertools;
use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};
use once_cell::sync::Lazy;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyInit, block_padding::{NoPadding, Pkcs7}};
use std::fs::File;
use std::io::{BufReader, Read};
use num::PrimInt;

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

pub static AES_KEY: Lazy<Vec<u8>> = Lazy::new(|| generate_aes_key());

pub static IV: Lazy<Vec<u8>> = Lazy::new(|| generate_aes_key());

pub static NONCE: Lazy<u64> = Lazy::new(|| rand::random::<u64>());

pub static DICT_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    let contents = fs::read_to_string("/usr/share/dict/words").unwrap();
    let lines: Vec<&str> = contents.lines().collect();

    lines[rand::random_range(0..lines.len())].as_bytes().to_vec()
});

pub fn file_to_string(path: &str) -> String {
    let file_in = File::open(path).unwrap();
    let mut reader_in = BufReader::new(file_in);
    let mut contents = String::new();
    reader_in.read_to_string(&mut contents).unwrap();

    contents.replace("\n", "")
}

pub fn file_to_bytes(path: &str) -> Vec<u8> {
    let file_in = File::open(path).unwrap();
    let mut reader_in = BufReader::new(file_in);
    let mut contents = Vec::new();
    reader_in.read_to_end(&mut contents).unwrap();

    contents
}

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
        .concat();

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

    ciphertext.concat()
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
        .concat()
}

pub fn unix_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

pub struct MT19937 {
    state_array: [u32; Self::N],
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

    pub fn new(seed: u32) -> Self {
        let mut seed = seed.clone();
        let mut state_array = [0; Self::N];vec![seed];
        state_array[0] = seed;

        for i in 1..Self::N {
            seed = Self::F.wrapping_mul(seed ^ (seed >> (Self::W-2))).wrapping_add(i as u32);
            state_array[i] = seed;
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

    pub fn new_from_slice(state_array: &[u32]) -> Self {
        Self {
            state_array: *state_array.as_array().unwrap(),
            index: 0,
        }
    }
}

// turn MT19937 into a stream cipher. same function for encrypting and decrypting
pub fn mt19937_stream_cipher(input: &[u8], seed: u32) -> Vec<u8> {
    let mut rng = MT19937::new(seed);
    input.chunks(4)
        .map(|block| xor_slice(block, &rng.random_u32().to_be_bytes()[..block.len()]))
        .concat()
}

pub fn crack_mt19937(bytes: &[u8], mut range: Range<u32>) -> Option<u32> {
    range.find(|&seed| {
        let mut rng = MT19937::new(seed);
        let candidate = bytes.chunks(4)
            .map(|_| rng.random_u32().to_be_bytes())
            .flatten()
            .collect_vec();

        candidate == bytes
    })
}

pub struct SHA1 {
    state: [u32; 5],
    message_len: u64,
    buffer: Vec<u8>,
}

impl SHA1 {
    pub fn new() -> Self {
        Self {
            state: [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
                0xC3D2E1F0,
            ],
            message_len: 0,
            buffer: Vec::new(),
        }
    }

    pub fn from_slice(state: &[u32], ml: u64) -> Self {
        Self {
            state: *state.as_array().unwrap(),
            message_len: ml,
            buffer: Vec::new(),
        }
    }

    pub fn process_block(&mut self, block: &[u8]) {
        assert!(block.len() == 64, "invalid block size");
        
        let mut words = block
            .chunks(4)
            .map(|word| u32::from_be_bytes(*word.as_array().unwrap()))
            .collect_vec();

        for i in 16..80 {
            words.push((words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16]).rotate_left(1));
        }

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for i in 0..80 {
            let (f, k);
            match i {
                0..20 => {
                    f = (b & c) | (!b & d);
                    k = 0x5A827999;
                },
                20..40 => {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                },
                40..60 => {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                },
                60..80 => {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                },
                _ => panic!("unexpected value")
            }

            let temp = a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(words[i]);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b); 
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }

    pub fn padding(byte_len: u64) -> Vec<u8> {
        let bit_len = byte_len << 3;
        let n_pad = (56 - (byte_len + 1) as isize).rem_euclid(64) as usize;
        [[0x80].as_slice(), &[0].repeat(n_pad), &bit_len.to_be_bytes()].concat()
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buffer.push(b);
            self.message_len += 1;
            if self.buffer.len() == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer.clear();
            }
        }
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        let padding = Self::padding(self.message_len);
        self.update(&padding);
        assert!(self.buffer.is_empty(), "invalid buffer state");
        self.state.map(|word| word.to_be_bytes()).concat()
    }

    pub fn digest(message: &[u8]) -> Vec<u8> {
        let mut sha1 = Self::new();
        sha1.update(message);
        sha1.finalize()
    }
}

pub struct MD4 {
    state: [u32; 4],
    message_len: u64,
    buffer: Vec<u8>,
}

impl MD4 {
    pub fn new() -> Self {
        Self {
            state: [
                0x67452301,
                0xEFCDAB89,
                0x98BADCFE,
                0x10325476,
            ],
            message_len: 0,
            buffer: Vec::new(),
        }
    }
    
    pub fn from_slice(state: &[u32], ml: u64) -> Self {
        Self {
            state: *state.as_array().unwrap(),
            message_len: ml,
            buffer: Vec::new(),
        }
    }
    
    pub fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }
    
    pub fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    
    pub fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }
    
    pub fn ff(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(Self::f(b, c, d)).wrapping_add(x).rotate_left(s);
    }
    
    pub fn gg(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(Self::g(b, c, d)).wrapping_add(x).wrapping_add(0x5A827999).rotate_left(s);
    }
    
    pub fn hh(a: &mut u32, b: u32, c: u32, d: u32, x: u32, s: u32) {
        *a = a.wrapping_add(Self::h(b, c, d)).wrapping_add(x).wrapping_add(0x6ED9EBA1).rotate_left(s);
    }

    pub fn process_block(&mut self, block: &[u8]) {
        assert!(block.len() == 64, "invalid block size");
        
        let words = block
            .chunks(4)
            .map(|word| u32::from_le_bytes(*word.as_array().unwrap()))
            .collect_vec();

        let [mut a, mut b, mut c, mut d] = self.state;

        // round 1
        Self::ff(&mut a, b, c, d, words[0],  3);
        Self::ff(&mut d, a, b, c, words[1],  7);
        Self::ff(&mut c, d, a, b, words[2],  11);
        Self::ff(&mut b, c, d, a, words[3],  19);
        Self::ff(&mut a, b, c, d, words[4],  3);
        Self::ff(&mut d, a, b, c, words[5],  7);
        Self::ff(&mut c, d, a, b, words[6],  11);
        Self::ff(&mut b, c, d, a, words[7],  19);
        Self::ff(&mut a, b, c, d, words[8],  3);
        Self::ff(&mut d, a, b, c, words[9],  7);
        Self::ff(&mut c, d, a, b, words[10], 11);
        Self::ff(&mut b, c, d, a, words[11], 19);
        Self::ff(&mut a, b, c, d, words[12], 3);
        Self::ff(&mut d, a, b, c, words[13], 7);
        Self::ff(&mut c, d, a, b, words[14], 11);
        Self::ff(&mut b, c, d, a, words[15], 19);

        // round 2
        Self::gg(&mut a, b, c, d, words[0],  3);
        Self::gg(&mut d, a, b, c, words[4],  5);
        Self::gg(&mut c, d, a, b, words[8],  9);
        Self::gg(&mut b, c, d, a, words[12], 13);
        Self::gg(&mut a, b, c, d, words[1],  3);
        Self::gg(&mut d, a, b, c, words[5],  5);
        Self::gg(&mut c, d, a, b, words[9],  9);
        Self::gg(&mut b, c, d, a, words[13], 13);
        Self::gg(&mut a, b, c, d, words[2],  3);
        Self::gg(&mut d, a, b, c, words[6],  5);
        Self::gg(&mut c, d, a, b, words[10], 9);
        Self::gg(&mut b, c, d, a, words[14], 13);
        Self::gg(&mut a, b, c, d, words[3],  3);
        Self::gg(&mut d, a, b, c, words[7],  5);
        Self::gg(&mut c, d, a, b, words[11], 9);
        Self::gg(&mut b, c, d, a, words[15], 13);

        // round 3
        Self::hh(&mut a, b, c, d, words[0],  3);
        Self::hh(&mut d, a, b, c, words[8],  9);
        Self::hh(&mut c, d, a, b, words[4],  11);
        Self::hh(&mut b, c, d, a, words[12], 15);
        Self::hh(&mut a, b, c, d, words[2],  3);
        Self::hh(&mut d, a, b, c, words[10], 9);
        Self::hh(&mut c, d, a, b, words[6],  11);
        Self::hh(&mut b, c, d, a, words[14], 15);
        Self::hh(&mut a, b, c, d, words[1],  3);
        Self::hh(&mut d, a, b, c, words[9],  9);
        Self::hh(&mut c, d, a, b, words[5],  11);
        Self::hh(&mut b, c, d, a, words[13], 15);
        Self::hh(&mut a, b, c, d, words[3],  3);
        Self::hh(&mut d, a, b, c, words[11], 9);
        Self::hh(&mut c, d, a, b, words[7],  11);
        Self::hh(&mut b, c, d, a, words[15], 15);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b); 
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }

    pub fn padding(byte_len: u64) -> Vec<u8> {
        let bit_len = byte_len << 3;
        let n_pad = (56 - (byte_len + 1) as isize).rem_euclid(64) as usize;
        [[0x80].as_slice(), &[0].repeat(n_pad), &bit_len.to_le_bytes()].concat()
    }

    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.buffer.push(b);
            self.message_len += 1;
            if self.buffer.len() == 64 {
                self.process_block(&self.buffer.clone());
                self.buffer.clear();
            }
        }
    }

    pub fn finalize(&mut self) -> Vec<u8> {
        let padding = Self::padding(self.message_len);
        self.update(&padding);
        assert!(self.buffer.is_empty(), "invalid buffer state");
        self.state.map(|word| word.to_le_bytes()).concat()
    }

    pub fn digest(message: &[u8]) -> Vec<u8> {
        let mut md4 = Self::new();
        md4.update(message);
        md4.finalize()
    }
}

pub fn hmac<F>(key: &[u8], message: &[u8], hash: F, block_size: usize) -> Vec<u8>
where F: Fn(&[u8]) -> Vec<u8>  {
    let block_key = if key.len() >= block_size {
        hash(key)
    }
    else {
        key.iter().copied().pad_using(block_size, |_| 0).collect()
    };

    let o_key_pad = xor_slice(&block_key, &vec![0x5c; block_size]);
    let i_key_pad = xor_slice(&block_key, &vec![0x36; block_size]);

    hash(&[o_key_pad, hash(&[&i_key_pad, message].concat())].concat())
}

pub fn modexp<T>(n: T, e: T, m: T) -> T
where T: PrimInt {
    assert!(e >= T::zero());
    
    if e == T::zero() {
        return T::one();
    }

    let mut result = T::one();
    let mut base = n % m;
    let mut exp = e;

    loop {
        if exp & T::one() == T::one() {
            result = (result * base) % m;
        }
        if exp == T::one() {
            return result;
        }
        base = base * base % m;
        exp = exp >> 1;
    }
}