use synchra_core::{crypto::{ChaosStreamCipher, FractalNode}, ChaosGenerator, FractalCipher, FractalEncoder, PostQuantumCrypto};

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

    fn test_chaos_stream_cipher() {
        let cipher = ChaosStreamCipher::new(20);
        let key = b"chaos_key_123";
        
        let test_cases = vec![
            b"Fractal secret".to_vec(),
            b"Hello, Synchra!".to_vec(),
            b"This is a longer test string to ensure everything works correctly".to_vec(),
        ];
    
        for (i, original) in test_cases.iter().enumerate() {
            println!("Test case {}:", i + 1);
            println!("Original: {:?}", original);
            
            let encrypted = cipher.encrypt(original, key);
            println!("Encrypted: {:?}", encrypted);
            
            let decrypted = cipher.decrypt(&encrypted, key);
            println!("Decrypted: {:?}", decrypted);
            
            // Añadimos más información de depuración
            println!("Original length: {}", original.len());
            println!("Decrypted length: {}", decrypted.len());
            
            if original.len() != decrypted.len() {
                println!("Length mismatch!");
            } else {
                for (j, (orig_byte, dec_byte)) in original.iter().zip(decrypted.iter()).enumerate() {
                    if orig_byte != dec_byte {
                        println!("Mismatch at index {}: original {:?}, decrypted {:?}", j, orig_byte, dec_byte);
                    }
                }
            }
            
            assert_eq!(original, &decrypted[..], "Test case {} failed", i + 1);
            println!("Test case {} passed", i + 1);
            println!();
        }
    
        // Añadimos una prueba adicional fuera del bucle
        let additional_test = b"Hello, Synchra!".to_vec();
        let encrypted = cipher.encrypt(&additional_test, key);
        let decrypted = cipher.decrypt(&encrypted, key);
        
        println!("Additional test:");
        println!("Original: {:?}", additional_test);
        println!("Encrypted: {:?}", encrypted);
        println!("Decrypted: {:?}", decrypted);
        
        assert_eq!(additional_test, decrypted, "Additional test failed");
        println!("Additional test passed");
    }

   fn test_fractal_cipher() {
    let cipher = FractalCipher::new(20, 1.5);
    let key = b"fractal_key_123";
    let original = b"Hello, Synchra!".to_vec();

    println!("Original: {:?}", original);

    // Ciframos el mismo mensaje varias veces
    for i in 1..=3 {
        let encrypted = cipher.encrypt(&original, key);
        let decrypted = cipher.decrypt(&encrypted, key);
        
        println!("Test {}", i);
        println!("Original: {:?}", original);
        println!("Encrypted: {:?}", encrypted);
        println!("Decrypted: {:?}", decrypted);
        
        assert_eq!(original, decrypted, "Test {} failed", i);
        println!("Test {} passed", i);
        println!();
    }
}
    
    fn test_chaos_generator() {
        let mut generator = ChaosGenerator::new();
        let entropy = generator.generate(32);
        assert_eq!(entropy.len(), 32);
    }

    // fn test_full_message_flow() {
    //     // Generar claves para Alice y Bob
    //     let (alice_pk, alice_sk) = PostQuantumCrypto::generate_keypair();
    //     let (bob_pk, bob_sk) = PostQuantumCrypto::generate_keypair();
    
    //     // Crear nodos de la red
    //     let nodes: Vec<FractalNode> = (0..10)
    //         .map(|i| FractalNode::new(format!("node_{}", i), vec![i; 32]))
    //         .collect();
    
    //     // Simular el envío de un mensaje
    //     let original_content = "Hello, Fractal World!";
    //     let received_content = simulate_message_flow(
    //         (&alice_pk, &alice_sk),
    //         (&bob_pk, &bob_sk),
    //         original_content,
    //         &nodes
    //     );
    
    //     println!("Original content: {}", original_content);
    //     println!("Received content: {:?}", received_content);
        
    //     assert_eq!(Some(original_content.to_string()), received_content);
    // }
    
    // test_full_message_flow();

    // test_fractal_cipher();
    // test_chaos_generator();
    // test_chaos_stream_cipher();
    // test_fractal_encoding();
    // test_post_quantum_crypto();
}