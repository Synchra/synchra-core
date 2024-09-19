use byteorder::{ByteOrder, LittleEndian};
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use sha3::{Digest, Sha3_256};
use num_complex::Complex64;
use std::f64::consts::PI;
pub struct PostQuantumCrypto;

impl PostQuantumCrypto {
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = kyber768::keypair();
        (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
    }

    pub fn encrypt(data: &[u8], public_key: &[u8]) -> Vec<u8> {
        let public_key = kyber768::PublicKey::from_bytes(public_key).unwrap();
        let (ciphertext, shared_secret) = kyber768::encapsulate(&public_key);
        let mut encrypted = ciphertext.as_bytes().to_vec();
        for (&a, &b) in data.iter().zip(shared_secret.as_bytes()) {
            encrypted.push(a ^ b);
        }
        encrypted
    }

    pub fn decrypt(encrypted: &[u8], secret_key: &[u8]) -> Vec<u8> {
        let secret_key = kyber768::SecretKey::from_bytes(secret_key).unwrap();
        let ciphertext_len = kyber768::ciphertext_bytes();
        let (ciphertext, data) = encrypted.split_at(ciphertext_len);
        let ciphertext = kyber768::Ciphertext::from_bytes(ciphertext).unwrap();
        let shared_secret = kyber768::decapsulate(&ciphertext, &secret_key);
        let mut decrypted = Vec::new();
        for (&a, &b) in data.iter().zip(shared_secret.as_bytes()) {
            decrypted.push(a ^ b);
        }
        decrypted
    }
}
pub struct FractalCipher {
    iterations: u32,
}

impl FractalCipher {
    pub fn new(iterations: u32) -> Self {
        FractalCipher { iterations }
    }

    fn complex_to_bytes(&self, c: Complex64) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        LittleEndian::write_f64(&mut bytes[0..8], c.re);
        LittleEndian::write_f64(&mut bytes[8..16], c.im);
        bytes
    }

    fn bytes_to_complex(&self, bytes: &[u8]) -> Complex64 {
        let re = LittleEndian::read_f64(&bytes[0..8]);
        let im = LittleEndian::read_f64(&bytes[8..16]);
        Complex64::new(re, im)
    }

    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut encrypted = Vec::new();
        let key_complex = self.key_to_complex(key);
        for &byte in data {
            let c = self.bytes_to_complex(&[byte]);
            let encrypted_complex = self.julia_map(c, key_complex);
            encrypted.extend_from_slice(&self.complex_to_bytes(encrypted_complex));
        }
        encrypted
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Vec<[u8; 16]> {
        let mut decrypted = Vec::new();
        let key_complex = self.key_to_complex(key);
        for chunk in encrypted.chunks(16) {
            let c = self.bytes_to_complex(chunk);
            let decrypted_complex = self.inverse_julia_map(c, key_complex);
            decrypted.push(self.complex_to_bytes(decrypted_complex));
        }
        decrypted
    }

    fn key_to_complex(&self, key: &[u8]) -> Complex64 {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let result = hasher.finalize();
        let real = f64::from_bits(u64::from_le_bytes(result[0..8].try_into().unwrap()));
        let imag = f64::from_bits(u64::from_le_bytes(result[8..16].try_into().unwrap()));
        Complex64::new(real, imag)
    }

    fn julia_map(&self, z: Complex64, c: Complex64) -> Complex64 {
        let mut z = z;
        for _ in 0..self.iterations {
            z = z * z + c;
        }
        z
    }

    fn inverse_julia_map(&self, z: Complex64, c: Complex64) -> Complex64 {
        let mut z = z;
        for _ in 0..self.iterations {
            z = (z - c).sqrt();
            if z.re < 0.0 {
                z = -z;
            }
        }
        z
    }
}