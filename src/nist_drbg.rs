// Minimal AES-256 CTR-DRBG used by NIST KAT generators (PQCgenKAT style).
// State: Key (32 bytes), V (16 bytes). Seed length: 48 bytes.

use aes::Aes256;
use cipher::{BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;

pub struct NistDrbg {
    key: [u8; 32],
    v:   [u8; 16],
}

impl NistDrbg {
    pub fn new(seed48: &[u8; 48]) -> Self {
        let mut drbg = Self { key: [0u8; 32], v: [0u8; 16] };
        drbg.update(Some(seed48));
        drbg
    }

    fn aes256_encrypt_block(key: &[u8; 32], block16: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(block16);
        cipher.encrypt_block(&mut block);
        let mut out = [0u8; 16];
        out.copy_from_slice(&block);
        out
    }

    fn inc_v(v: &mut [u8; 16]) {
        for i in (0..16).rev() {
            let (nv, carry) = v[i].overflowing_add(1);
            v[i] = nv;
            if !carry { break; }
        }
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];

        for i in 0..3 {
            Self::inc_v(&mut self.v);
            let block = Self::aes256_encrypt_block(&self.key, &self.v);
            temp[i * 16..(i + 1) * 16].copy_from_slice(&block);
        }

        if let Some(pd) = provided {
            for i in 0..48 {
                temp[i] ^= pd[i];
            }
        }

        self.key.copy_from_slice(&temp[0..32]);
        self.v.copy_from_slice(&temp[32..48]);
    }

    pub fn randombytes(&mut self, out: &mut [u8]) {
        let mut pos = 0usize;
        while pos < out.len() {
            Self::inc_v(&mut self.v);
            let block = Self::aes256_encrypt_block(&self.key, &self.v);
            let take = core::cmp::min(16, out.len() - pos);
            out[pos..pos + take].copy_from_slice(&block[..take]);
            pos += take;
        }
        self.update(None);
    }
}
