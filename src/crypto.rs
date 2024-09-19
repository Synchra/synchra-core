use num_complex::Complex64;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use shamir_secret_sharing::{num_bigint::{BigInt, Sign}, ShamirSecretSharing as SSS};
use std::f64::consts::PI;
use byteorder::{ByteOrder, LittleEndian};
use bincode;
use secret_sharing_and_dkg::shamir_ss::{deal_secret, deal_random_secret};
use ark_ff::PrimeField;
use ark_bls12_381::Fr;
use ark_std::rand::rngs::OsRng;
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

fn print_message_details(message: &FractalMessage) {
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

    pub fn encrypt(data: &[u8], public_key: &[u8]) -> Vec<u8> {
        let public_key = kyber768::PublicKey::from_bytes(public_key).unwrap();
        let (ciphertext, shared_secret) = kyber768::encapsulate(&public_key);
        
        let mut encrypted = ciphertext.as_bytes().to_vec();
        let mut xored_data = data.to_vec();
        for (a, &b) in xored_data.iter_mut().zip(shared_secret.as_bytes().iter().cycle()) {
            *a ^= b;
        }
        encrypted.extend(xored_data);
        
        encrypted
    }

    pub fn decrypt(encrypted: &[u8], secret_key: &[u8]) -> Vec<u8> {
        let secret_key = kyber768::SecretKey::from_bytes(secret_key).unwrap();
        let ciphertext_len = kyber768::ciphertext_bytes();
        let (ciphertext, data) = encrypted.split_at(ciphertext_len);
        let ciphertext = kyber768::Ciphertext::from_bytes(ciphertext).unwrap();
        let shared_secret = kyber768::decapsulate(&ciphertext, &secret_key);
        
        let mut decrypted = data.to_vec();
        for (a, &b) in decrypted.iter_mut().zip(shared_secret.as_bytes().iter().cycle()) {
            *a ^= b;
        }
        decrypted
    }
}
pub struct FractalCipher {
    iterations: u32,
    scale: f64,
}

impl FractalCipher {
    pub fn new(iterations: u32, scale: f64) -> Self {
        FractalCipher { 
            iterations,
            scale,
        }
    }

    pub fn encrypt(&self, data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        thread_rng().fill(&mut nonce);
        
        let mut encrypted = nonce.to_vec();
        let keystream = self.generate_keystream(data.len(), key, &nonce);
        encrypted.extend(data.iter().zip(keystream.iter()).map(|(&b, &k)| b ^ k));
        encrypted
    }

    pub fn decrypt(&self, encrypted: &[u8], key: &[u8]) -> Vec<u8> {
        let (nonce, data) = encrypted.split_at(16);
        let keystream = self.generate_keystream(data.len(), key, nonce);
        data.iter().zip(keystream.iter()).map(|(&b, &k)| b ^ k).collect()
    }

    fn generate_keystream(&self, length: usize, key: &[u8], nonce: &[u8]) -> Vec<u8> {
        let key_complex = self.key_to_complex(key, nonce);
        let mut z = Complex64::new(0.0, 0.0);
        let mut keystream = Vec::with_capacity(length);

        while keystream.len() < length {
            z = self.julia_map(z, key_complex);
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

    fn julia_map(&self, mut z: Complex64, c: Complex64) -> Complex64 {
        for _ in 0..self.iterations {
            z = z * z + c;
            if z.norm() > 2.0 * self.scale {
                z *= self.scale / z.norm();
            }
        }
        z
    }

    pub fn fie_encode(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for chunk in data.chunks(16) {
            let mut complex_chunk = self.bytes_to_complex(chunk);
            complex_chunk = self.julia_map(complex_chunk, Complex64::new(0.5, 0.5));
            encoded.extend_from_slice(&self.complex_to_bytes(complex_chunk));
        }
        encoded
    }

    pub fn fie_decode(&self, encoded: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        for chunk in encoded.chunks(16) {
            let mut complex_chunk = self.bytes_to_complex(chunk);
            complex_chunk = self.inverse_julia_map(complex_chunk, Complex64::new(0.5, 0.5));
            decoded.extend_from_slice(&self.complex_to_bytes(complex_chunk));
        }
        decoded.truncate(encoded.len());
        decoded
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

    fn inverse_julia_map(&self, mut z: Complex64, c: Complex64) -> Complex64 {
        for _ in 0..self.iterations {
            z = (z - c).sqrt();
            if z.norm() > 2.0 * self.scale {
                z *= -1.0;
            }
        }
        z
    }
}



// Nuevas estructuras
pub struct ShamirSecretSharing {
    sss: SSS,
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

impl ShamirSecretSharing {
    pub fn new(threshold: u8, total_shares: u8) -> Self {
        let prime = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
            .expect("Failed to parse prime");
        
        ShamirSecretSharing {
            sss: SSS {
                threshold: threshold as usize,
                share_amount: total_shares as usize,
                prime,
            }
        }
    }

    pub fn split(&self, secret: &[u8]) -> Vec<Vec<u8>> {
        let secret_bigint = BigInt::from_bytes_be(Sign::Plus, secret);
        let shares = self.sss.split(secret_bigint);
        
        shares.into_iter()
            .map(|(index, share)| {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&(index as u32).to_be_bytes());
                bytes.extend_from_slice(&share.to_bytes_be().1);
                bytes
            })
            .collect()
    }

    pub fn reconstruct(&self, shares: &[Vec<u8>]) -> Vec<u8> {
        let shares: Vec<(usize, BigInt)> = shares.iter()
            .map(|bytes| {
                let index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
                let share = BigInt::from_bytes_be(Sign::Plus, &bytes[4..]);
                (index, share)
            })
            .collect();

        if shares.len() < self.sss.threshold {
            panic!("Not enough shares to reconstruct the secret");
        }

        let reconstructed = self.sss.recover(&shares[..self.sss.threshold]);
        reconstructed.to_bytes_be().1
    }
}

impl FractalMessage {
    pub fn new(sender: Vec<u8>, recipient: Vec<u8>, content: Vec<u8>) -> Self {
        let id = Self::generate_id(&sender, &recipient, &content);
        FractalMessage {
            id,
            sender,
            recipient,
            content,
        }
    }

    fn generate_id(sender: &[u8], recipient: &[u8], content: &[u8]) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(sender);
        hasher.update(recipient);
        hasher.update(content);
        hex::encode(hasher.finalize())
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

pub fn fragment_message(message: &FractalMessage, sss: &ShamirSecretSharing) -> Vec<MessageFragment> {
    let serialized_message = bincode::serialize(&message).expect("Failed to serialize message");
    let shares = sss.split(&serialized_message);
    
    shares.clone()
        .into_iter()
        .enumerate()
        .map(|(i, share)| MessageFragment {
            fragment_id: format!("{}_frag_{}", message.id, i),
            fragment_index: i as u8,
            total_fragments: shares.len() as u8,
            fragment_data: share,
            next_hop: format!("node_{}", rand::thread_rng().gen_range(0..10)),
        })
        .collect()
}

pub fn reconstruct_message(fragments: &[MessageFragment], sss: &ShamirSecretSharing) -> Result<FractalMessage, String> {
    let shares: Vec<Vec<u8>> = fragments.iter().map(|f| f.fragment_data.clone()).collect();
    
    let reconstructed_data = sss.reconstruct(&shares);
    
    match bincode::deserialize(&reconstructed_data) {
        Ok(message) => Ok(message),
        Err(e) => Err(format!("Deserialization error: {}. Reconstructed data length: {}", e, reconstructed_data.len())),
    }
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

    // #[test]
    // fn test_fractal_cipher_encode_decode() {
    //     let fractal_cipher = FractalCipher::new(10, 1.5);
    //     let original_data = b"Hello, Fractal World!";
    //     let encoded_data = fractal_cipher.fie_encode(original_data);
    //     let decoded_data = fractal_cipher.fie_decode(&encoded_data);
    //     assert_eq!(original_data, &decoded_data[..]);
    // }

    // #[test]
    // fn test_post_quantum_crypto_encrypt_decrypt() {
    //     let (public_key, secret_key) = PostQuantumCrypto::generate_keypair();
    //     let original_data = b"Secret message";
    //     let encrypted_data = PostQuantumCrypto::encrypt(original_data, &public_key);
    //     let decrypted_data = PostQuantumCrypto::decrypt(&encrypted_data, &secret_key);
    //     assert_eq!(original_data, &decrypted_data[..]);
    // }

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
    fn test_fragment_and_reconstruct_message() {
        let sss = ShamirSecretSharing::new(3, 5);
        let original_message = FractalMessage::new(
            vec![1; 32],
            vec![2; 32],
            b"Test content".to_vec(),
        );
        let fragments = fragment_message(&original_message, &sss);
        assert_eq!(fragments.len(), 5);
        
        match reconstruct_message(&fragments[..5], &sss) {
            Ok(reconstructed) => {
                println!("Original message:");
                print_message_details(&original_message);

                let reconstructed = reconstruct_message(&fragments[..3], &sss).expect("Failed to reconstruct message");
                println!("Reconstructed message:");
                print_message_details(&reconstructed);
                assert_eq!(original_message, reconstructed);
            },
            Err(e) => {
                panic!("Failed to reconstruct message: {}", e);
            }
        }
    }

    // #[test]
    // fn test_route_fragment() {
    //     let nodes: Vec<FractalNode> = (0..10)
    //         .map(|i| FractalNode::new(format!("node_{}", i), vec![i; 32]))
    //         .collect();
    //     let fragment = MessageFragment {
    //         fragment_id: "test_frag".to_string(),
    //         fragment_index: 0,
    //         total_fragments: 1,
    //         fragment_data: vec![0; 32],
    //         next_hop: "node_5".to_string(),
    //     };
    //     let route = route_fragment(&fragment, &nodes);
    //     assert!(!route.is_empty());
    //     assert_eq!(route[0].id, "node_5");
    // }

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