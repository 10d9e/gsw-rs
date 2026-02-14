//! Gadget matrix operations: BitDecomp, BitDecompInverse, Flatten, PowersOf2.
//!
//! The gadget matrix G enables efficient decomposition of Z_q elements into binary.
//! G = (1, 2, 4, ..., 2^{l-1}) ⊗ I_{n+1} in Z_q^{N × N} where N = (n+1)*l.

use crate::modular::mod_q;
use crate::params::Params;

/// BitDecomp: decompose vector v in Z_q^{k} into binary vector in {0,1}^{k*l}.
/// Output[v[j]*l + i] = (v[j] >> i) & 1 for i in 0..l, j in 0..k.
pub fn bit_decomp(v: &[u64], params: &Params) -> Vec<u64> {
    let l = params.l;
    let mut result = Vec::with_capacity(v.len() * l);
    for &vi in v {
        for i in 0..l {
            result.push(((vi >> i) & 1) as u64);
        }
    }
    result
}

/// BitDecompInverse: reconstruct Z_q element from decomposition.
/// Input vector of length k*l; each chunk of l elements encodes one Z_q value.
/// Uses full values (not just & 1) to preserve carries from homomorphic addition.
pub fn bit_decomp_inverse(bits: &[u64], params: &Params) -> Vec<u64> {
    let l = params.l;
    let k = bits.len() / l;
    let q = params.q;
    let mut result = Vec::with_capacity(k);
    for j in 0..k {
        let mut sum: i64 = 0;
        for i in 0..l {
            // Use full value to preserve carries (e.g. 1+1=2 in addition)
            sum += (bits[j * l + i] as i64) * (1i64 << i);
        }
        result.push(mod_q(sum, q));
    }
    result
}

/// Flatten: BitDecomp(BitDecompInverse(x)) - ensures vector is in binary form.
pub fn flatten(v: &[u64], params: &Params) -> Vec<u64> {
    let decomposed = bit_decomp_inverse(v, params);
    bit_decomp(&decomposed, params)
}

/// PowersOf2: transform vector b in Z_q^{k} to [b[0], 2*b[0], ..., 2^{l-1}*b[0], b[1], ...].
/// This gives the "inverse" structure: for bit_vec = BitDecomp(v), we have
/// PowersOf2(BitDecompInverse(bit_vec)) encodes the same info.
pub fn powers_of_2(b: &[u64], params: &Params) -> Vec<u64> {
    let l = params.l;
    let q = params.q;
    let mut result = Vec::with_capacity(b.len() * l);
    for &bi in b {
        for i in 0..l {
            let p = 1u64 << i;
            result.push(mod_q((bi as i64) * (p as i64), q));
        }
    }
    result
}

/// G^{-1}(M): For matrix M, returns binary matrix X such that G*X = M (over Z_q).
/// Here we compute row-wise: for each row of M, BitDecomp gives the row of X.
/// Output is M with each row replaced by its bit decomposition (binary).
pub fn g_inverse_matrix(matrix: &[Vec<u64>], params: &Params) -> Vec<Vec<u64>> {
    matrix
        .iter()
        .map(|row| {
            let decomp = bit_decomp(row, params);
            decomp
        })
        .collect()
}

/// Apply Flatten to each row of a matrix (in place structure).
/// Input: N x N matrix. Each row is flattened.
pub fn flatten_matrix(matrix: &[Vec<u64>], params: &Params) -> Vec<Vec<u64>> {
    matrix
        .iter()
        .map(|row| {
            let flat = flatten(row, params);
            flat
        })
        .collect()
}
