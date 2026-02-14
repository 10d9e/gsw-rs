//! Bootstrapping for GSW FHE.
//!
//! Bootstrapping refreshes a noisy ciphertext by homomorphically evaluating
//! the decryption circuit. This requires an evaluation key containing
//! encryptions of the secret key bits under the same secret key (circular security).

use rand::Rng;

use crate::gadget::{bit_decomp, flatten_matrix, powers_of_2};
use crate::gsw::{encrypt, homomorphic_add, Ciphertext, GswPublicKey, GswSecretKey};
use crate::modular::mod_q;
use crate::params::Params;

/// Evaluation key: encryption of each bit of the secret key.
#[derive(Clone, Debug)]
pub struct EvaluationKey {
    pub encryptions: Vec<Ciphertext>,
    #[allow(dead_code)]
    params: Params,
}

/// Generate the evaluation key for bootstrapping.
pub fn gen_evaluation_key<R: Rng>(
    rng: &mut R,
    sk: &GswSecretKey,
    pk: &GswPublicKey,
) -> EvaluationKey {
    let params = sk.params();
    let bits = bit_decomp(&sk.s, params);

    let encryptions: Vec<Ciphertext> = bits
        .iter()
        .map(|&b| encrypt(rng, pk, b as u8))
        .collect();

    EvaluationKey {
        encryptions,
        params: params.clone(),
    }
}

/// Homomorphic linear combination: compute Enc(sum of c_i * x_i) from Enc(x_i).
fn homomorphic_linear_fixed(
    params: &Params,
    cts: &[Ciphertext],
    coefficients: &[u64],
) -> Ciphertext {
    assert_eq!(cts.len(), coefficients.len());
    let n = params.n_expanded;
    let q = params.q;

    let mut result = None;

    for (ct, &coeff) in cts.iter().zip(coefficients.iter()) {
        if coeff == 0 {
            continue;
        }

        let mut scaled = vec![vec![0u64; n]; n];
        for i in 0..n {
            for j in 0..n {
                scaled[i][j] = mod_q((ct[i][j] as i64) * (coeff as i64), q);
            }
        }
        let scaled_flat = flatten_matrix(&scaled, params);

        result = Some(match result {
            None => scaled_flat,
            Some(acc) => homomorphic_add(params, &acc, &scaled_flat),
        });
    }

    result.unwrap_or_else(|| vec![vec![0u64; n]; n])
}

/// Compute the decryption linear part in the clear (for verification).
/// Matches decrypt: C[l-1] · v
pub fn decrypt_linear_part_clear(sk: &GswSecretKey, ct: &Ciphertext) -> u64 {
    let params = sk.params();
    let q = params.q;
    let l = params.l;
    let n_expanded = params.n_expanded;
    let row_idx = l - 1;

    let v = powers_of_2(&sk.s, params);
    let mut dot: i64 = 0;
    for j in 0..n_expanded {
        dot += (ct[row_idx][j] as i64) * (v[j] as i64);
    }
    mod_q(dot, q)
}

/// Bootstrap a noisy ciphertext to reduce its noise.
/// Homomorphically computes C[l-1] · v where v = PowersOf2(s).
pub fn bootstrap(
    params: &Params,
    noisy_ct: &Ciphertext,
    ek: &EvaluationKey,
) -> Ciphertext {
    let l = params.l;
    let n_expanded = params.n_expanded;
    let row_idx = l - 1;
    let q = params.q;

    let mut coefficients = vec![0u64; n_expanded];
    let c_row = &noisy_ct[row_idx];

    for i in 0..n_expanded {
        let block = i / l;
        let k = i % l;
        let mut coef: i64 = 0;
        for j_bit in 0..l {
            let j = block * l + j_bit;
            let term = mod_q(
                (c_row[j] as i64) * ((1i64 << (k + j_bit)) as i64),
                q,
            ) as i64;
            coef = mod_q(coef + term, q) as i64;
        }
        coefficients[i] = mod_q(coef, q) as u64;
    }

    homomorphic_linear_fixed(params, &ek.encryptions, &coefficients)
}
