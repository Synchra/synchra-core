use num_complex::Complex64;
use std::f64::consts::PI;

pub struct FractalEncoder {
    max_iterations: u32,
    escape_radius: f64,
}

impl FractalEncoder {
    pub fn new(max_iterations: u32, escape_radius: f64) -> Self {
        FractalEncoder {
            max_iterations,
            escape_radius,
        }
    }

    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::new();
        for &byte in data {
            let c = self.byte_to_complex(byte);
            let iterations = self.mandelbrot_iterations(c);
            encoded.push(iterations as u8);
        }
        encoded
    }

    pub fn decode(&self, encoded: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        for &iterations in encoded {
            let byte = self.complex_to_byte(iterations);
            decoded.push(byte);
        }
        decoded
    }

    fn byte_to_complex(&self, byte: u8) -> Complex64 {
        let x = (byte as f64 / 255.0) * 4.0 - 2.0;
        let y = (byte as f64 / 255.0) * 4.0 - 2.0;
        Complex64::new(x, y)
    }

    fn complex_to_byte(&self, iterations: u8) -> u8 {
        ((iterations as f64 / self.max_iterations as f64) * 255.0) as u8
    }

    fn mandelbrot_iterations(&self, c: Complex64) -> u32 {
        let mut z = Complex64::new(0.0, 0.0);
        for i in 0..self.max_iterations {
            if z.norm() > self.escape_radius {
                return i;
            }
            z = z * z + c;
        }
        self.max_iterations
    }
}