//! LWE/GSW parameter definitions.
//!
//! Parameters are chosen for correctness with conservative security levels.
//! In production, use lattice estimators for proper security parameter selection.

/// Security level in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Toy parameters for testing (~32-bit security)
    Toy,
    /// Low security (~64-bit)
    Low,
    /// Medium security (~128-bit)
    Medium,
}

/// LWE/GSW instance parameters.
#[derive(Clone, Debug)]
pub struct Params {
    /// Modulus q (must be power of 2 for gadget)
    pub q: u64,
    /// Lattice dimension n
    pub n: usize,
    /// Number of bits to represent q: l = log2(q)
    pub l: usize,
    /// N = (n+1) * l - dimension of expanded gadget space
    pub n_expanded: usize,
    /// Number of LWE samples for public key (columns of A)
    pub m: usize,
    /// Error bound B for discrete uniform error distribution [-B, B]
    pub error_bound: i64,
}

impl Params {
    /// Create parameters for the given security level.
    ///
    /// Parameters are chosen so that correctness never fails:
    /// - Error growth: mult multiplies error by ~N=(n+1)*l, add doubles it
    /// - Requirement: N * sqrt(m) * B ≪ q/4 for one multiplication
    pub fn new(level: SecurityLevel) -> Self {
        let mut p = match level {
            SecurityLevel::Toy => Self {
                q: 1 << 20,   // 1M - margin for correctness
                n: 8,
                m: 256,
                error_bound: 1,
                l: 0,
                n_expanded: 0,
            },
            SecurityLevel::Low => Self {
                q: 1 << 24,
                n: 24,
                m: 384,
                error_bound: 2,
                l: 0,
                n_expanded: 0,
            },
            SecurityLevel::Medium => Self {
                q: 1 << 26,
                n: 48,
                m: 768,
                error_bound: 4,
                l: 0,
                n_expanded: 0,
            },
        };
        p.with_derived();
        p
    }

    /// Create toy parameters for quick testing.
    pub fn toy() -> Self {
        Self::new(SecurityLevel::Toy)
    }

    fn with_derived(&mut self) {
        self.l = (self.q as f64).log2() as usize;
        self.n_expanded = (self.n + 1) * self.l;
    }
}
