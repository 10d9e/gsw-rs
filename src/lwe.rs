//! LWE (Learning With Errors) primitives.

use rand::Rng;

use crate::modular::mod_q;
use crate::params::Params;

/// Secret key: vector t in Z_q^n. Stored as (1, -t) for GSW compatibility.
#[derive(Clone, Debug)]
pub struct SecretKey {
    /// Full secret vector s = (1, -t_1, ..., -t_n) in Z_q^{n+1}
    pub s: Vec<u64>,
    params: Params,
}

impl SecretKey {
    pub fn params(&self) -> &Params {
        &self.params
    }
}

/// Public key: LWE matrix A where b = A*s + e (approximately).
/// Stored as matrix of shape (m, n+1) with first column being b.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Matrix A where each row is (b_i, a_i1, ..., a_in)
    pub a: Vec<Vec<u64>>,
    params: Params,
}

impl PublicKey {
    pub fn params(&self) -> &Params {
        &self.params
    }
}

/// Generate a random value in Z_q.
fn rand_zq<R: Rng>(rng: &mut R, q: u64) -> u64 {
    rng.gen_range(0..q)
}

/// Generate a small error in [-B, B] for LWE.
fn sample_error<R: Rng>(rng: &mut R, bound: i64) -> i64 {
    if bound <= 0 {
        return 0;
    }
    rng.gen_range(-bound..=bound)
}

/// Generate secret key: random t in Z_q^n, return s = (1, -t).
pub fn keygen<R: Rng>(rng: &mut R, params: &Params) -> (SecretKey, PublicKey) {
    let n = params.n;
    let m = params.m;
    let q = params.q;
    let bound = params.error_bound;

    // Secret vector t in Z_q^n
    let t: Vec<u64> = (0..n).map(|_| rand_zq(rng, q)).collect();

    // s = (1, -t_1, ..., -t_n)
    let mut s = vec![1u64];
    for &ti in &t {
        s.push(mod_q(-(ti as i64), q));
    }

    // Public key: A = [b | B] where b = B*t + e
    let b_mat: Vec<Vec<u64>> = (0..m)
        .map(|_| (0..n).map(|_| rand_zq(rng, q)).collect())
        .collect();

    let e: Vec<i64> = (0..m).map(|_| sample_error(rng, bound)).collect();

    let mut b = vec![0u64; m];
    for i in 0..m {
        let mut dot: i64 = 0;
        for j in 0..n {
            dot += b_mat[i][j] as i64 * t[j] as i64;
        }
        b[i] = mod_q(dot + e[i], q);
    }

    let mut a = vec![vec![0u64; n + 1]; m];
    for i in 0..m {
        a[i][0] = b[i];
        for j in 0..n {
            a[i][j + 1] = b_mat[i][j];
        }
    }

    (
        SecretKey {
            s: s.clone(),
            params: params.clone(),
        },
        PublicKey {
            a,
            params: params.clone(),
        },
    )
}
