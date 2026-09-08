#[cfg(test)]
mod tests {
    use std::{ops::Range, thread, time::{Duration, SystemTime, UNIX_EPOCH}};

    use crate::core::*;

    fn rng_delay() -> (u32, u32) {
        thread::sleep(Duration::from_secs(rand::random_range(40..500)));
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut rng = MT19937::new(&seed);
        thread::sleep(Duration::from_secs(rand::random_range(40..500)));
        (seed, rng.random_u32())
    }

    fn crack_mt19937_seed(output: u32, mut range: Range<u32>) -> Option<u32> {
        range.find(|&seed| {
            let mut rng = MT19937::new(&seed);
            rng.random_u32() == output
        })
    }

    #[test]
    fn s03_c06_cracking_an_mt19937_seed() {
        let (real_seed, generated) = rng_delay();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let recovered_seed = crack_mt19937_seed(generated, now - 30 * 60..now);

        assert_eq!(real_seed, recovered_seed.unwrap());
    }
}