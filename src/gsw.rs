//! GSW (Gentry-Sahai-Waters) homomorphic encryption scheme.

use rand::Rng;

use crate::gadget::{bit_decomp, flatten_matrix, powers_of_2};
use crate::lwe::{keygen, PublicKey, SecretKey};
use crate::modular::mod_q;
use crate::params::Params;

/// GSW ciphertext: an N×N matrix over Z_q.
pub type Ciphertext = Vec<Vec<u64>>;

/// GSW secret key (same as LWE secret for this construction).
pub type GswSecretKey = SecretKey;

/// GSW public key.
pub type GswPublicKey = PublicKey;

/// Generate GSW key pair.
pub fn gsw_keygen<R: Rng>(rng: &mut R, params: &Params) -> (GswSecretKey, GswPublicKey) {
    keygen(rng, params)
}

/// Encrypt a single bit μ ∈ {0, 1}.
///
/// C = Flatten(μ*I + BitDecomp(R*A))
/// where R is a random binary matrix of size N×m.
pub fn encrypt<R: Rng>(rng: &mut R, pk: &GswPublicKey, bit: u8) -> Ciphertext {
    let params = pk.params();
    let n_expanded = params.n_expanded;
    let m = params.m;
    let q = params.q;

    // R: N×m binary random matrix
    let r: Vec<Vec<u64>> = (0..n_expanded)
        .map(|_| (0..m).map(|_| rng.gen_range(0..=1) as u64).collect())
        .collect();

    // RA = R * A (over Z_q)
    let mut ra = vec![vec![0u64; params.n + 1]; n_expanded];
    for i in 0..n_expanded {
        for j in 0..(params.n + 1) {
            let mut sum: i64 = 0;
            for k in 0..m {
                sum += (r[i][k] as i64) * (pk.a[k][j] as i64);
            }
            ra[i][j] = mod_q(sum, q);
        }
    }

    // BitDecomp(RA) - each row of RA is decomposed
    let bit_decomp_ra: Vec<Vec<u64>> = ra
        .iter()
        .map(|row| bit_decomp(row, params))
        .collect();

    // μ*I + BitDecomp(RA)
    let mut sum = bit_decomp_ra;
    for i in 0..n_expanded {
        sum[i][i] = mod_q((sum[i][i] as i64) + (bit as i64), q);
    }

    // Flatten each row
    flatten_matrix(&sum, params)
}

/// Decrypt a GSW ciphertext.
///
/// Uses C[l-1] · v / v[l-1] as in the reference implementation, where v = PowersOf2(s).
pub fn decrypt(sk: &GswSecretKey, ct: &Ciphertext) -> u8 {
    let params = sk.params();
    let q = params.q;
    let l = params.l;
    let n_expanded = params.n_expanded;

    let v = powers_of_2(&sk.s, params);
    let row_idx = l - 1;

    let mut dot: i64 = 0;
    for j in 0..n_expanded {
        dot += (ct[row_idx][j] as i64) * (v[j] as i64);
    }
    let val = mod_q(dot, q) as i64;

    let scale = v[l - 1] as i64;
    if scale == 0 {
        return 0;
    }

    let msg = ((val as f64) / (scale as f64)).round() as i64;
    (msg.rem_euclid(2)).abs() as u8
}

/// Homomorphic addition: C_+ = C_1 + C_2 (then Flatten).
pub fn homomorphic_add(params: &Params, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
    let q = params.q;
    let n_expanded = params.n_expanded;
    let mut sum = vec![vec![0u64; n_expanded]; n_expanded];
    for i in 0..n_expanded {
        for j in 0..n_expanded {
            sum[i][j] = mod_q(
                (ct1[i][j] as i64) + (ct2[i][j] as i64),
                q,
            );
        }
    }
    flatten_matrix(&sum, params)
}

/// Homomorphic multiplication: C_× = Flatten(C_1 * C_2).
///
/// Uses direct matrix multiplication (C implementation approach).
pub fn homomorphic_mult(params: &Params, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
    let q = params.q;
    let n_expanded = params.n_expanded;

    let mut prod = vec![vec![0u64; n_expanded]; n_expanded];
    for i in 0..n_expanded {
        for j in 0..n_expanded {
            let mut sum: i64 = 0;
            for k in 0..n_expanded {
                sum += (ct1[i][k] as i64) * (ct2[k][j] as i64);
            }
            prod[i][j] = mod_q(sum, q);
        }
    }
    flatten_matrix(&prod, params)
}

/// Homomorphic NAND: C_nand = Flatten(I - C_1 * C_2).
pub fn homomorphic_nand(params: &Params, ct1: &Ciphertext, ct2: &Ciphertext) -> Ciphertext {
    let q = params.q;
    let n_expanded = params.n_expanded;

    let mut prod = vec![vec![0u64; n_expanded]; n_expanded];
    for i in 0..n_expanded {
        for j in 0..n_expanded {
            let mut sum: i64 = 0;
            for k in 0..n_expanded {
                sum += (ct1[i][k] as i64) * (ct2[k][j] as i64);
            }
            prod[i][j] = mod_q(sum, q);
        }
    }

    let mut result = vec![vec![0u64; n_expanded]; n_expanded];
    for i in 0..n_expanded {
        for j in 0..n_expanded {
            let val = if i == j {
                mod_q(1 - (prod[i][j] as i64), q)
            } else {
                mod_q(-(prod[i][j] as i64), q)
            };
            result[i][j] = val;
        }
    }
    flatten_matrix(&result, params)
}
