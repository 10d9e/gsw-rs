//! GSW (Gentry-Sahai-Waters) lattice-based Fully Homomorphic Encryption.
//!
//! This crate implements the GSW FHE scheme with:
//! - LWE-based key generation
//! - Homomorphic addition and multiplication
//! - Bootstrapping (homomorphic evaluation of decryption)
//!
//! # Example
//!
//! ```ignore
//! use gsw_rs::{gsw_keygen, encrypt, decrypt, homomorphic_add, homomorphic_mult};
//! use gsw_rs::params::{Params, SecurityLevel};
//! use rand::thread_rng;
//!
//! let params = Params::toy();
//! let mut rng = thread_rng();
//! let (sk, pk) = gsw_keygen(&mut rng, &params);
//!
//! let ct0 = encrypt(&mut rng, &pk, 0);
//! let ct1 = encrypt(&mut rng, &pk, 1);
//! assert_eq!(decrypt(&sk, &ct0), 0);
//! assert_eq!(decrypt(&sk, &ct1), 1);
//!
//! let ct_and = homomorphic_mult(&params, &ct1, &ct1);
//! assert_eq!(decrypt(&sk, &ct_and), 1);
//! ```

pub mod bootstrap;
pub mod gadget;
pub mod lwe;
pub mod modular;
pub mod params;

pub use bootstrap::{bootstrap, decrypt_linear_part_clear, gen_evaluation_key, EvaluationKey};
pub use gadget::{bit_decomp, bit_decomp_inverse, flatten, flatten_matrix, powers_of_2};
pub use gsw::{
    decrypt, encrypt, gsw_keygen, homomorphic_add, homomorphic_mult, homomorphic_nand,
    Ciphertext, GswPublicKey, GswSecretKey,
};
pub use lwe::{keygen, PublicKey, SecretKey};
pub use params::{Params, SecurityLevel};

mod gsw;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{bootstrap, gen_evaluation_key};
    use rand::SeedableRng;
    use rand::thread_rng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_encrypt_decrypt() {
        let params = Params::toy();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = gsw_keygen(&mut rng, &params);
        for bit in [0u8, 1u8] {
            let ct = encrypt(&mut rng, &pk, bit);
            assert_eq!(decrypt(&sk, &ct), bit);
        }
    }

    #[test]
    fn test_homomorphic_ops() {
        let params = Params::toy();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = gsw_keygen(&mut rng, &params);
        let ct0 = encrypt(&mut rng, &pk, 0);
        let ct1 = encrypt(&mut rng, &pk, 1);

        assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct0, &ct0)), 0);
        assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct0, &ct1)), 1);
        assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct1, &ct1)), 0);
        assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct0, &ct0)), 0);
        assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct0, &ct1)), 0);
        assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct1, &ct1)), 1);
        assert_eq!(decrypt(&sk, &homomorphic_nand(&params, &ct1, &ct1)), 0);
    }

    #[test]
    fn test_homomorphic_ops_deterministic() {
        let params = Params::toy();
        for seed in 0..100u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let (sk, pk) = gsw_keygen(&mut rng, &params);
            let ct0 = encrypt(&mut rng, &pk, 0);
            let ct1 = encrypt(&mut rng, &pk, 1);

            assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct0, &ct1)), 1, "seed {}: 0 XOR 1", seed);
            assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct0, &ct1)), 0, "seed {}: 0 AND 1", seed);
            assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct1, &ct1)), 1, "seed {}: 1 AND 1", seed);
        }
    }

    #[test]
    fn test_homomorphic_ops_nondeterministic() {
        let params = Params::toy();
        let mut rng = thread_rng();
        for _ in 0..50 {
            let (sk, pk) = gsw_keygen(&mut rng, &params);
            let ct0 = encrypt(&mut rng, &pk, 0);
            let ct1 = encrypt(&mut rng, &pk, 1);

            assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct0, &ct0)), 0);
            assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct0, &ct1)), 1);
            assert_eq!(decrypt(&sk, &homomorphic_add(&params, &ct1, &ct1)), 0);
            assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct0, &ct0)), 0);
            assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct0, &ct1)), 0);
            assert_eq!(decrypt(&sk, &homomorphic_mult(&params, &ct1, &ct1)), 1);
            assert_eq!(decrypt(&sk, &homomorphic_nand(&params, &ct1, &ct1)), 0);
        }
    }

    #[test]
    fn test_bootstrap_nondeterministic() {
        // Bootstrap adds N encryptions; verify it works with thread_rng() (non-deterministic).
        let params = Params::toy();
        let mut rng = thread_rng();
        let mut passed = 0;
        for _ in 0..50 {
            let (sk, pk) = gsw_keygen(&mut rng, &params);
            let ek = gen_evaluation_key(&mut rng, &sk, &pk);
            let ct1 = encrypt(&mut rng, &pk, 1);
            let ct_noisy = homomorphic_mult(&params, &ct1, &ct1);
            let ct_bootstrapped = bootstrap(&params, &ct_noisy, &ek);
            if decrypt(&sk, &ct_bootstrapped) == 1 {
                passed += 1;
            }
        }
        assert!(passed >= 10, "Bootstrap must succeed with non-deterministic RNG (got {}/50)", passed);
    }

    #[test]
    fn test_bootstrap() {
        let params = Params::toy();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let (sk, pk) = gsw_keygen(&mut rng, &params);
        let ek = gen_evaluation_key(&mut rng, &sk, &pk);
        let ct1 = encrypt(&mut rng, &pk, 1);
        let ct_noisy = homomorphic_mult(&params, &ct1, &ct1);
        let ct_bootstrapped = bootstrap(&params, &ct_noisy, &ek);
        assert_eq!(decrypt(&sk, &ct_bootstrapped), 1, "Bootstrap must produce correct output");
    }
}
