#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::fs::File;
    use std::io::{BufReader, Read};

    use crate::core::*;

    #[test]
    fn s03_c05_implementing_the_mersenne_twister_rng() {
        let file_in = File::open("src/set_03/chal_05.txt").unwrap();
        let mut reader_in = BufReader::new(file_in);
        let mut contents = String::new();
        reader_in.read_to_string(&mut contents).unwrap();
        let expected = contents
            .split("\n")
            .map(|string| string.parse::<u32>().unwrap())
            .collect_vec();

        let n = 500;
        let seed = 1131464071;
        let mut rng = MT19937::new(seed);
        let generated = (0..n).map(|_| rng.random_u32()).collect_vec();
        assert_eq!(generated, expected[..n]);
    }
}