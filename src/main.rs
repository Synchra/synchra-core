use synchra_core::{FractalEncoder, PostQuantumCrypto, FractalCipher, ChaosGenerator};

fn main() {
    fn test_fractal_encoding() {
        let encoder = FractalEncoder::new(1, 16.0);
        let original = b"Hello, Synchra!";
        let encoded = encoder.encode(original);
        let decoded = encoder.decode(&encoded);
        assert_eq!(original, &decoded[..]);
    }

    fn test_post_quantum_crypto() {
        let (private_key, public_key) = PostQuantumCrypto::generate_keypair();
        let original = b"Secret message";
        let encrypted = PostQuantumCrypto::encrypt(original, &public_key);
        let decrypted = PostQuantumCrypto::decrypt(&encrypted, &private_key);
        assert_eq!(original, &decrypted[..]);
    }

    fn test_fractal_cipher() {
        let cipher = FractalCipher::new(1);
        let key = b"fractal_key_123";
        let original = b"Fractal secret";
        let encrypted = cipher.encrypt(original, key);
        let decrypted = cipher.decrypt(&encrypted, key);
        // assert_eq!(original, &decrypted[..]);
    }

    fn test_chaos_generator() {
        let mut generator = ChaosGenerator::new();
        let entropy = generator.generate(32);
        assert_eq!(entropy.len(), 32);
    }

    test_chaos_generator();
    test_fractal_cipher();
    test_fractal_encoding();
    test_post_quantum_crypto();
}
