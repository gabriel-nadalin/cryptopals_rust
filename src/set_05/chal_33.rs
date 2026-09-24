#[cfg(test)]
mod tests {
    use num::{BigUint, FromPrimitive, bigint::RandBigInt};

    use crate::core::*;

    #[test]
    fn s05_c33_implementing_diffie_hellman() {
        let p = 37_u64;
        let g = 5_u64;

        let a = rand::random::<u64>() % p;
        let big_a = modexp(g, a, p);

        let b = rand::random::<u64>() % p;
        let big_b = modexp(g, b, p);

        let s = modexp(big_b, a, p);
        let s_prime = modexp(big_a, b, p);

        assert_eq!(s, s_prime);

        let p_string = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff";
        let p = BigUint::from_bytes_be(&hex_to_bytes(p_string));
        let g = BigUint::from_u32(2).unwrap();

        let a = rand_08::thread_rng().gen_biguint_below(&p);
        let big_a = g.modpow(&a, &p);
        
        let b = rand_08::thread_rng().gen_biguint_below(&p);
        let big_b = g.modpow(&b, &p);
        
        let s = big_b.modpow(&a, &p);
        let s_prime = big_a.modpow(&b, &p);

        assert_eq!(s, s_prime);
    }
}