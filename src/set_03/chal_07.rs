#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::core::*;

    fn untemper(output: &u32) -> u32 {
        let mut y = output ^ (output >> MT19937::L);

        y = y ^ ((y << MT19937::T) & MT19937::C);

        let mut aux_mask = 0x0000007f_u32 << MT19937::S;
        for _ in 0..4 {
            y = y ^ (((y << MT19937::S) & MT19937::B) & aux_mask);
            aux_mask <<= MT19937::S;
        }

        let mut aux_mask = 0xffe00000_u32 >> MT19937::U;
        for _ in 0..2 {
            y = y ^ ((y >> MT19937::U) & aux_mask);
            aux_mask >>= MT19937::U;
        }

        y
    }

    #[test]
    fn s03_c07_cloning_an_mt19937_rng_from_its_output() {
        let mut rng = MT19937::new(&rand::random());
        let recovered_state = (0..624)
            .map(|_| untemper(&rng.random_u32()))
            .collect_vec();
        let mut spliced_rng = MT19937::new_from_vec(recovered_state);

        for _ in 0..10000 {
            assert_eq!(spliced_rng.random_u32(), rng.random_u32());
        }
    }
}