#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use crate::core::*;

    fn rng_delay() -> (u32, u32) {
        thread::sleep(Duration::from_secs(rand::random_range(40..500)));
        let seed = unix_time();
        let mut rng = MT19937::new(seed);
        thread::sleep(Duration::from_secs(rand::random_range(40..500)));
        (rng.random_u32(), seed)
    }

    #[test]
    fn s03_c22_cracking_an_mt19937_seed() {
        let (generated, real_seed) = rng_delay();

        let now = unix_time();
        let recovered_seed = (now - 30 * 60..now)
            .find(|&seed| {
                let mut rng = MT19937::new(seed);
                rng.random_u32() == generated
            })
            .expect("seed not found in range");

        assert_eq!(real_seed, recovered_seed);
    }
}