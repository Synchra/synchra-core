use num_complex::Complex64;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use shamir_secret_sharing::{num_bigint::{BigInt, Sign}, ShamirSecretSharing as SSS};
use ssss::{gen_shares, unlock, SsssConfig};
use core::str;
use std::f64::consts::PI;
use byteorder::{ByteOrder, LittleEndian};
use bincode;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};
pub struct PostQuantumCrypto;

pub struct ChaosStreamCipher {
    iterations: u32,
}

impl ChaosStreamCipher {
    pub fn new(iterations: u32) -> Self {
        ChaosStreamCipher { iterations }
    }

    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        self.process(data, key)
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Vec<u8> {
        self.process(encrypted, key)
    }

    fn process(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut x = self.key_to_float(key);
        data.iter().map(|&byte| {
            x = self.logistic_map(x);
            byte ^ (x * 256.0) as u8
        }).collect()
    }

    fn key_to_float(&self, key: &[u8]) -> f64 {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        let result = hasher.finalize();
        let mut sum: u64 = 0;
        for &byte in result.iter().take(8) {
            sum = sum.wrapping_shl(8) | byte as u64;
        }
        (sum as f64) / (u64::MAX as f64)
    }

    fn logistic_map(&self, x: f64) -> f64 {
        let mut x = x;
        for _ in 0..self.iterations {
            x = 3.99 * x * (1.0 - x);
        }
        x
    }
}

pub fn print_message_details(message: &FractalMessage) {
    println!("Message ID: {}", message.id);
    println!("Sender length: {}", message.sender.len());
    println!("Recipient length: {}", message.recipient.len());
    println!("Content length: {}", message.content.len());
    println!("Content (as UTF-8 if possible): {}", String::from_utf8_lossy(&message.content));
}

impl PostQuantumCrypto {
    pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let (public_key, secret_key) = kyber768::keypair();
        (public_key.as_bytes().to_vec(), secret_key.as_bytes().to_vec())
    }

    fn derive_aes_key(shared_secret: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.finalize().into()
    }

    pub fn encrypt(data: &[u8], public_key: &[u8]) -> Vec<u8> {
        println!("Encryption details:");
        println!("  Input data length: {}", data.len());
        
        let public_key = match kyber768::PublicKey::from_bytes(public_key) {
            Ok(pk) => pk,
            Err(e) => {
                println!("Error creating PublicKey: {:?}", e);
                return Vec::new();
            }
        };
        
        let (ciphertext, shared_secret) = kyber768::encapsulate(&public_key);
        
        let mut encrypted = Vec::new();
        let ciphertext_len = ciphertext.as_bytes().len() as u32;
        encrypted.extend_from_slice(&ciphertext_len.to_le_bytes());
        encrypted.extend_from_slice(ciphertext.as_bytes());
        
        println!("  Kyber ciphertext length: {}", ciphertext.as_bytes().len());
        println!("  Shared secret length: {}", shared_secret.as_bytes().len());
        
        let aes_key = Self::derive_aes_key(shared_secret.as_bytes());
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        encrypted.extend_from_slice(&nonce_bytes);
        
        let encrypted_data = match cipher.encrypt(nonce, data) {
            Ok(ed) => ed,
            Err(e) => {
                println!("AES encryption failed: {:?}", e);
                return Vec::new();
            }
        };
        encrypted.extend(encrypted_data.clone());
        
        println!("  Nonce length: {}", nonce_bytes.len());
        println!("  AES data length: {}", encrypted_data.len());
        println!("  Total encrypted length: {}", encrypted.len());
        
        encrypted
    }

    pub fn decrypt(encrypted: &[u8], secret_key: &[u8]) -> Vec<u8> {
        println!("Decryption details:");
        println!("  Total encrypted length: {}", encrypted.len());
        
        if encrypted.len() < 4 {
            println!("Encrypted data is too short for ciphertext length");
            return Vec::new();
        }

        let (ciphertext_len_bytes, rest) = encrypted.split_at(4);
        let ciphertext_len = u32::from_le_bytes(ciphertext_len_bytes.try_into().unwrap()) as usize;
        println!("  Expected ciphertext length: {}", ciphertext_len);
        
        if rest.len() < ciphertext_len {
            println!("Encrypted data is too short for Kyber ciphertext");
            return Vec::new();
        }

        let (ciphertext, rest) = rest.split_at(ciphertext_len);
        println!("  Actual ciphertext length: {}", ciphertext.len());
        println!("  Remaining data length: {}", rest.len());

        if rest.len() < 12 {
            println!("Remaining data is too short for nonce");
            return Vec::new();
        }

        let (nonce, aes_ciphertext) = rest.split_at(12);
        println!("  Nonce length: {}", nonce.len());
        println!("  AES ciphertext length: {}", aes_ciphertext.len());

        let secret_key = match kyber768::SecretKey::from_bytes(secret_key) {
            Ok(sk) => sk,
            Err(e) => {
                println!("Error creating SecretKey: {:?}", e);
                return Vec::new();
            }
        };

        let ciphertext = match kyber768::Ciphertext::from_bytes(ciphertext) {
            Ok(ct) => ct,
            Err(e) => {
                println!("Error creating Ciphertext: {:?}", e);
                return Vec::new();
            }
        };

        let shared_secret = kyber768::decapsulate(&ciphertext, &secret_key);
        println!("  Shared secret length: {}", shared_secret.as_bytes().len());

        let aes_key = Self::derive_aes_key(shared_secret.as_bytes());
        let key = Key::<Aes256Gcm>::from_slice(&aes_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);

        match cipher.decrypt(nonce, aes_ciphertext) {
            Ok(decrypted) => {
                println!("Decryption successful. Decrypted length: {}", decrypted.len());
                decrypted
            },
            Err(e) => {
                println!("Decryption failed: {:?}", e);
                Vec::new()
            }
        }
    }
}

pub struct FractalCipher {
    iterations: u32,
    scale: f64,
}

impl FractalCipher {
    pub fn new(iterations: u32, scale: f64) -> Self {
        FractalCipher { iterations, scale }
    }
    
    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        thread_rng().fill(&mut nonce);
        
        let mut encrypted = nonce.to_vec();
        let key_complex = self.key_to_complex(key, &nonce);
        let keystream = self.generate_keystream(data.len(), key_complex);
        encrypted.extend(data.iter().zip(keystream.iter()).map(|(&b, &k)| b ^ k));
        encrypted
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Vec<u8> {
        if encrypted.len() < 16 {
            panic!("Encrypted data is too short");
        }
        let (nonce, data) = encrypted.split_at(16);
        let key_complex = self.key_to_complex(key, nonce);
        let keystream = self.generate_keystream(data.len(), key_complex);
        data.iter().zip(keystream.iter()).map(|(&b, &k)| b ^ k).collect()
    }

    fn generate_keystream(&self, length: usize, key_complex: Complex64) -> Vec<u8> {
        let mut z = key_complex;
        let mut keystream = Vec::with_capacity(length);

        while keystream.len() < length {
            z = self.julia_map(z);
            let bytes = self.complex_to_bytes(z);
            keystream.extend_from_slice(&bytes);
        }

        keystream.truncate(length);
        keystream
    }

    fn key_to_complex(&self, key: &[u8], nonce: &[u8]) -> Complex64 {
        let mut hasher = Sha3_256::new();
        hasher.update(key);
        hasher.update(nonce);
        let result = hasher.finalize();
        let real = f64::from_bits(u64::from_le_bytes(result[0..8].try_into().unwrap()));
        let imag = f64::from_bits(u64::from_le_bytes(result[8..16].try_into().unwrap()));
        Complex64::new(real.sin() * self.scale, imag.cos() * self.scale)
    }

    pub fn fie_encode(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for &byte in data {
            let complex = self.byte_to_complex(byte);
            let mapped = self.julia_map(complex);
            encoded.extend_from_slice(&self.complex_to_bytes(mapped));
        }
        encoded
    }

    pub fn fie_decode(&self, encoded: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        for chunk in encoded.chunks(16) {
            let complex = self.bytes_to_complex(chunk);
            let unmapped = self.inverse_julia_map(complex);
            decoded.push(self.complex_to_byte(unmapped));
        }
        decoded
    }

    fn byte_to_complex(&self, byte: u8) -> Complex64 {
        Complex64::new(byte as f64 / 255.0, 0.0)
    }

    fn complex_to_byte(&self, c: Complex64) -> u8 {
        (c.re.clamp(0.0, 1.0) * 255.0).round() as u8
    }

    fn bytes_to_complex(&self, bytes: &[u8]) -> Complex64 {
        let mut padded_bytes = [0u8; 16];
        let copy_len = std::cmp::min(bytes.len(), 16);
        padded_bytes[..copy_len].copy_from_slice(&bytes[..copy_len]);
        let real = LittleEndian::read_f64(&padded_bytes[0..8]);
        let imag = LittleEndian::read_f64(&padded_bytes[8..16]);
        Complex64::new(real, imag)
    }

    fn complex_to_bytes(&self, c: Complex64) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        LittleEndian::write_f64(&mut bytes[0..8], c.re);
        LittleEndian::write_f64(&mut bytes[8..16], c.im);
        bytes
    }

    fn julia_map(&self, z: Complex64) -> Complex64 {
        let c = Complex64::new(0.5, 0.5);
        z * z + c
    }

    fn inverse_julia_map(&self, w: Complex64) -> Complex64 {
        let c = Complex64::new(0.5, 0.5);
        let sqrt = (w - c).sqrt();
        if sqrt.re >= 0.0 { sqrt } else { -sqrt }
    }
}



#[derive(Serialize, Deserialize)]
struct SerializableBigInt(String);

impl From<BigInt> for SerializableBigInt {
    fn from(n: BigInt) -> Self {
        SerializableBigInt(n.to_string())
    }
}

impl From<SerializableBigInt> for BigInt {
    fn from(s: SerializableBigInt) -> Self {
        s.0.parse().unwrap()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FractalMessage {
    pub id: String,
    pub sender: Vec<u8>,
    pub recipient: Vec<u8>,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MessageFragment {
    fragment_id: String,
    fragment_index: u8,
    total_fragments: u8,
    fragment_data: Vec<u8>,
    next_hop: String,
}

#[derive(Clone)]
pub struct FractalNode {
    id: String,
    public_key: Vec<u8>,
}

pub struct ShamirSecretSharing {
    config: SsssConfig,
}

impl ShamirSecretSharing {
    pub fn new(threshold: u8, total_shares: u8) -> Self {
        let mut config = SsssConfig::default();
        config.set_num_shares(total_shares);
        config.set_threshold(threshold);
        
        ShamirSecretSharing { config }
    }

    pub fn split(&self, secret: &[u8]) -> Vec<Vec<u8>> {
        let secret_str = str::from_utf8(secret).expect("Invalid UTF-8");
        gen_shares(&self.config, secret_str.as_bytes())
            .expect("Failed to generate shares")
            .into_iter()
            .map(|s| s.into_bytes())
            .collect()
    }

    pub fn reconstruct(&self, shares: &[Vec<u8>]) -> Vec<u8> {
        let string_shares: Vec<String> = shares
            .iter()
            .map(|s| String::from_utf8(s.to_vec()).expect("Invalid UTF-8"))
            .collect();
        
        unlock(&string_shares)
            .expect("Failed to reconstruct secret")
    }
}

impl FractalMessage {
    pub fn new(sender: Vec<u8>, recipient: Vec<u8>, content: Vec<u8>) -> Self {
        let id = format!("{:x}", md5::compute(&content));
        FractalMessage {
            id,
            sender,
            recipient,
            content,
        }
    }
}

impl FractalNode {
    pub fn new(id: String, public_key: Vec<u8>) -> Self {
        FractalNode { id, public_key }
    }

    pub fn process_fragment(&self, fragment: &MessageFragment, total_nodes: usize) -> MessageFragment {
        let mut new_fragment = fragment.clone();
        new_fragment.next_hop = format!("node_{}", thread_rng().gen_range(0..total_nodes));
        new_fragment
    }
}

pub fn fragment_message(message: &FractalMessage, sss: &ShamirSecretSharing) -> Vec<Vec<u8>> {
    let serialized_message = bincode::serialize(&message).expect("Failed to serialize message");
    sss.split(&serialized_message)
}

pub fn reconstruct_message(fragments: &[Vec<u8>], sss: &ShamirSecretSharing) -> Result<FractalMessage, String> {
    let reconstructed_data = sss.reconstruct(fragments);
    bincode::deserialize(&reconstructed_data)
        .map_err(|e| format!("Deserialization error: {}. Reconstructed data length: {}", e, reconstructed_data.len()))
}

pub fn route_fragment(fragment: &MessageFragment, nodes: &[FractalNode]) -> Vec<FractalNode> {
    let mut path = Vec::new();
    let mut current_fragment = fragment.clone();
    
    println!("Routing fragment: {:?}", current_fragment.fragment_id);
    
    for _ in 0..5 {
        println!("Looking for node: {}", current_fragment.next_hop);
        if let Some(node) = nodes.iter().find(|n| n.id == current_fragment.next_hop) {
            println!("Found node: {}", node.id);
            path.push(node.clone());
            current_fragment = node.process_fragment(&current_fragment, nodes.len());
        } else {
            println!("Node not found: {}", current_fragment.next_hop);
            break;
        }
    }
    
    println!("Path length: {}", path.len());
    path
}

// pub fn simulate_message_flow(
//     sender_key: (&[u8], &[u8]),
//     recipient_key: (&[u8], &[u8]),
//     content: &str,
//     nodes: &[FractalNode]
// ) -> Option<String> {
//     let fractal_cipher = FractalCipher::new(10, 1.5);
//     let sss = ShamirSecretSharing::new(3, 5);
    
//     println!("Original content: {}", content);
    
//    
//     let encoded_content = fractal_cipher.fie_encode(content.as_bytes());
//     println!("Encoded content length: {}", encoded_content.len());
    
//     let message = FractalMessage::new(
//         sender_key.0.to_vec(),
//         recipient_key.0.to_vec(),
//         encoded_content.clone()
//     );
    
//     println!("Message created with ID: {}", message.id);
    
//    
//     let encrypted_content = PostQuantumCrypto::encrypt(&encoded_content, recipient_key.0);
//     println!("Encrypted content length: {}", encrypted_content.len());
    
//     let encrypted_message = FractalMessage {
//         content: encrypted_content,
//         ..message
//     };
    
//     println!("Message encrypted");
    
//   
//     let fragments = fragment_message(&encrypted_message, &sss);
    
//     println!("Message fragmented into {} parts", fragments.len());
    
//    
//     let mut routed_fragments = Vec::new();
//     for fragment in &fragments {
//         let path = route_fragment(fragment, nodes);
//         println!("Fragment {} route: {:?}", fragment.fragment_id, path.iter().map(|n| &n.id).collect::<Vec<_>>());
//         routed_fragments.push(fragment.clone());
//     }
    
//    
//     println!("Attempting to reconstruct message");
//     if let Some(reconstructed_message) = reconstruct_message(&routed_fragments, &sss) {
//         println!("Message reconstructed successfully");
//         println!("Reconstructed content length: {}", reconstructed_message.content.len());
        
//         let decrypted_content = PostQuantumCrypto::decrypt(&reconstructed_message.content, recipient_key.1);
//         println!("Decrypted content length: {}", decrypted_content.len());
        
//         let original_content = fractal_cipher.fie_decode(&decrypted_content);
//         println!("Decoded content length: {}", original_content.len());
        
//         match String::from_utf8(original_content) {
//             Ok(s) => {
//                 println!("Decrypted content: {}", s);
//                 Some(s)
//             },
//             Err(e) => {
//                 println!("Failed to convert decrypted content to string: {}", e);
//                 println!("First 20 bytes of decrypted content: {:?}", &decrypted_content[..20.min(decrypted_content.len())]);
//                 None
//             }
//         }
//     } else {
//         println!("Failed to reconstruct message");
//         None
//     }
// }


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fractal_cipher_encode_decode() {
        let fractal_cipher = FractalCipher::new(10, 1.5);
        let original_data = b"Hello, Fractal World! 1234568790abcdfgasdfuqwwoieurzncxv.----___3499499239459841908470ajhdflalsdf";
        println!("Original data: {:?}", original_data);
        println!("Original data length: {}", original_data.len());

        let encoded_data = fractal_cipher.fie_encode(original_data);
        println!("Encoded data: {:?}", encoded_data);
        println!("Encoded data length: {}", encoded_data.len());

        let decoded_data = fractal_cipher.fie_decode(&encoded_data);
        println!("Decoded data: {:?}", decoded_data);
        println!("Decoded data length: {}", decoded_data.len());
        println!("En español: {:?}", std::str::from_utf8(decoded_data.as_slice()).unwrap());

        assert_eq!(original_data, &decoded_data[..], 
            "Original and decoded data do not match.\nOriginal: {:?}\nDecoded: {:?}", 
            original_data, decoded_data);
    }

    #[test]
    fn test_julia_map_inverse() {
        let fractal_cipher = FractalCipher::new(10, 1.5);
        let original = Complex64::new(1.0, 1.0);
        
        let mapped = fractal_cipher.julia_map(original);
        println!("Original: {:?}", original);
        println!("Mapped: {:?}", mapped);
        
        let unmapped = fractal_cipher.inverse_julia_map(mapped);
        println!("Unmapped: {:?}", unmapped);
        
        assert!((original - unmapped).norm() < 1e-10, 
            "Julia map is not perfectly invertible. Original: {:?}, Unmapped: {:?}", original, unmapped);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let fractal_cipher = FractalCipher::new(10, 1.5);
        let original_data = b"Hello, Fractal World!";
        let key = b"SecretKey123";

        let encrypted = fractal_cipher.encrypt(original_data, key);
        let decrypted = fractal_cipher.decrypt(&encrypted, b"SecretKey123");
        let bad_decrypted = fractal_cipher.decrypt(&encrypted, b"SecretKey123_");

        assert_eq!(original_data, &decrypted[..], 
            "Encryption/Decryption failed");

        assert!(original_data != &bad_decrypted[..], 
            "Bad Key - Encryption/Decryption failed");
    }

    #[test]
    fn test_bytes_complex_conversion() {
        let fractal_cipher = FractalCipher::new(10, 1.5);
        let original_bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let complex = fractal_cipher.bytes_to_complex(&original_bytes);
        let converted_bytes = fractal_cipher.complex_to_bytes(complex);
        assert_eq!(original_bytes, converted_bytes, "Bytes to complex and back conversion failed");
    }

    #[test]
    fn test_generate_keypair() {
        let (public_key, secret_key) = PostQuantumCrypto::generate_keypair();
        assert_eq!(public_key.len(), kyber768::public_key_bytes());
        assert_eq!(secret_key.len(), kyber768::secret_key_bytes());
    }

    #[test]
    fn test_derive_aes_key() {
        let dummy_secret = vec![0u8; 32];
        let aes_key = PostQuantumCrypto::derive_aes_key(&dummy_secret);
        assert_eq!(aes_key.len(), 32);
    }

    #[test]
    fn test_kyber_encapsulate_decapsulate() {
        let (public_key, secret_key) = kyber768::keypair();
        let (shared_secret1, ciphertext) = kyber768::encapsulate(&public_key);
        let shared_secret2 = kyber768::decapsulate(&ciphertext, &secret_key);
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let plaintext = b"test message";
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .expect("encryption failure!");
        let decrypted = cipher.decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!");
        
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_detailed_encrypt_decrypt() {
        let (public_key, secret_key) = PostQuantumCrypto::generate_keypair();
        println!("Public key length: {}", public_key.len());
        println!("Secret key length: {}", secret_key.len());

        // Test with non-empty message
        let message = b"test message";
        println!("Original message: {:?}", message);

        let encrypted = PostQuantumCrypto::encrypt(message, &public_key);
        println!("Encrypted data length: {}", encrypted.len());
        println!("Encrypted data: {:?}", &encrypted);

        // Print detailed information about encrypted data structure
        println!("\nDetailed encrypted data structure:");
        println!("Total encrypted length: {}", encrypted.len());
        println!("Ciphertext length bytes: {:?}", &encrypted[..4]);
        let ciphertext_len = u32::from_le_bytes(encrypted[..4].try_into().unwrap()) as usize;
        println!("Ciphertext length: {}", ciphertext_len);
        println!("Ciphertext: {:?}", &encrypted[4..4+ciphertext_len]);
        println!("Nonce: {:?}", &encrypted[4+ciphertext_len..4+ciphertext_len+12]);
        println!("AES ciphertext: {:?}", &encrypted[4+ciphertext_len+12..]);

        let decrypted = PostQuantumCrypto::decrypt(&encrypted, &secret_key);
        println!("Decrypted message: {:?}", decrypted);

        assert_eq!(message, &decrypted[..], "Decrypted message does not match original message");

        // Test with empty message
        let empty_message = b"";
        println!("\nEmpty message: {:?}", empty_message);

        let encrypted_empty = PostQuantumCrypto::encrypt(empty_message, &public_key);
        println!("Encrypted empty data length: {}", encrypted_empty.len());
        println!("Encrypted empty data: {:?}", &encrypted_empty);

        let decrypted_empty = PostQuantumCrypto::decrypt(&encrypted_empty, &secret_key);
        println!("Decrypted empty message: {:?}", decrypted_empty);

        assert_eq!(empty_message, &decrypted_empty[..], "Decrypted empty message does not match original empty message");

        // Print Kyber parameters
        println!("\nKyber parameters:");
        println!("Public key bytes: {}", kyber768::public_key_bytes());
        println!("Secret key bytes: {}", kyber768::secret_key_bytes());
        println!("Ciphertext bytes: {}", kyber768::ciphertext_bytes());
        println!("Shared secret bytes: {}", kyber768::shared_secret_bytes());

        // Test decryption with incorrect key
        println!("\nTesting decryption with incorrect key:");
        let (_, incorrect_key) = PostQuantumCrypto::generate_keypair();
        let decrypted_incorrect = PostQuantumCrypto::decrypt(&encrypted, &incorrect_key);
        println!("Decrypted message with incorrect key: {:?}", decrypted_incorrect);
        assert!(decrypted_incorrect.is_empty(), "Decryption with incorrect key should fail");
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let sss = ShamirSecretSharing::new(3, 5);
        let secret = b"This is a secret message";
        let shares = sss.split(secret);
        assert_eq!(shares.len(), 5);
        let reconstructed = sss.reconstruct(&shares[0..3]);
        assert_eq!(secret, &reconstructed[..]);
    }

    #[test]
    fn test_various_secret_sizes() {
        let threshold = 3;
        let total_shares = 5;
        let sss = ShamirSecretSharing::new(threshold, total_shares);

        let sizes_to_test = [16, 24, 32, 48, 64, 128];

        for &size in &sizes_to_test {
            println!("Testing with secret size: {} bytes", size);

            let mut rng = rand::thread_rng();

            let secret: Vec<u8> = (0..size).map(|_| rng.gen_range(32..127) as u8).collect();
            println!("Original secret: {:?}", &secret[..32.min(secret.len())]);

            let shares = sss.split(&secret);
            println!("  Generated {} shares", shares.len());
            println!("  First share length: {} bytes", shares[0].len());
            println!("  First share content: {:?}", &shares[0][..20.min(shares[0].len())]);

            let reconstructed_secret = sss.reconstruct(&shares[..threshold as usize]);
            println!("  Reconstructed secret length: {} bytes", reconstructed_secret.len());
            println!("  Reconstructed secret: {:?}", &reconstructed_secret[..32.min(reconstructed_secret.len())]);

            assert_eq!(secret, reconstructed_secret, "Reconstructed secret does not match original for size {}", size);
            println!("  Success: Secret successfully reconstructed!");

            // Test with fewer shares
            let mut reduced_shares = shares.clone();
            reduced_shares.truncate(threshold as usize);
            let reconstructed_secret = sss.reconstruct(&reduced_shares);
            assert_eq!(secret, reconstructed_secret, "Reconstructed secret does not match original with minimum shares for size {}", size);
            println!("  Success: Secret successfully reconstructed with minimum shares!");
        }
    }

    #[test]
    fn test_fragment_and_reconstruct_message() {
        let sss = ShamirSecretSharing::new(5, 12);
        let original_message = FractalMessage::new(
            vec![1; 32],
            vec![2; 32],
            b"Hola hijo de puta macho me caog en la puta virgen de oros como lea esto me corro".to_vec(),
        );
        let fragments = fragment_message(&original_message, &sss);
        assert_eq!(fragments.len(), 12);
        
        println!("Original message:");
        print_message_details(&original_message);

        let reconstructed = reconstruct_message(&fragments[..5], &sss).expect("Failed to reconstruct message");
        println!("Reconstructed message:");
        print_message_details(&reconstructed);
        
        assert_eq!(original_message, reconstructed);
        println!("Success: Message successfully fragmented and reconstructed!");
        
        // Test with all fragments
        let reconstructed_all = reconstruct_message(&fragments, &sss).expect("Failed to reconstruct message with all fragments");
        assert_eq!(original_message, reconstructed_all);
        println!("Success: Message successfully reconstructed with all fragments!");
    }

    #[test]
    fn test_route_fragment() {
        let nodes: Vec<FractalNode> = (0..10)
            .map(|i| FractalNode::new(format!("node_{}", i), vec![i; 32]))
            .collect();
        let fragment = MessageFragment {
            fragment_id: "test_frag".to_string(),
            fragment_index: 0,
            total_fragments: 1,
            fragment_data: vec![0; 32],
            next_hop: "node_5".to_string(),
        };
        let route = route_fragment(&fragment, &nodes);
        assert!(!route.is_empty());
        assert_eq!(route[0].id, "node_5");
    }

    // #[test]
    // fn test_end_to_end_message_flow() {
    //     let (alice_pk, alice_sk) = PostQuantumCrypto::generate_keypair();
    //     let (bob_pk, bob_sk) = PostQuantumCrypto::generate_keypair();
    //     let nodes: Vec<FractalNode> = (0..10)
    //         .map(|i| FractalNode::new(format!("node_{}", i), vec![i; 32]))
    //         .collect();
    //     let original_content = "Hello, Fractal World!";
    //     let received_content = simulate_message_flow(
    //         (&alice_pk, &alice_sk),
    //         (&bob_pk, &bob_sk),
    //         original_content,
    //         &nodes
    //     );
    //     assert_eq!(Some(original_content.to_string()), received_content);
    // }
}
