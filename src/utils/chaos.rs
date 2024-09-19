use rand::Rng;

pub struct ChaosGenerator {
    x: f64,
    y: f64,
    z: f64,
}

impl ChaosGenerator {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        ChaosGenerator {
            x: rng.gen(),
            y: rng.gen(),
            z: rng.gen(),
        }
    }

    pub fn generate(&mut self, length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        for _ in 0..length {
            let (new_x, new_y, new_z) = self.lorenz_step();
            self.x = new_x;
            self.y = new_y;
            self.z = new_z;
            result.push((self.x * 256.0) as u8);
        }
        result
    }

    fn lorenz_step(&self) -> (f64, f64, f64) {
        let dt = 0.01;
        let sigma = 10.0;
        let rho = 28.0;
        let beta = 8.0 / 3.0;

        let dx = sigma * (self.y - self.x) * dt;
        let dy = (self.x * (rho - self.z) - self.y) * dt;
        let dz = (self.x * self.y - beta * self.z) * dt;

        (self.x + dx, self.y + dy, self.z + dz)
    }
}