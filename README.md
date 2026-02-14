# GSW-RS

A Rust implementation of the **GSW (Gentry–Sahai–Waters)** lattice-based fully homomorphic encryption scheme.

## Features

- **LWE-based key generation** — Learning With Errors for security
- **Bit encryption/decryption** — Encrypt bits 0 and 1
- **Homomorphic operations** — XOR (addition mod 2), AND (multiplication), NAND
- **Bootstrapping** — Homomorphic evaluation of the decryption circuit to refresh noisy ciphertexts

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

The demo shows key generation, encryption/decryption, homomorphic XOR/AND/NAND, and bootstrapping.

## Usage

```rust
use gsw_rs::{gsw_keygen, encrypt, decrypt, homomorphic_add, homomorphic_mult, homomorphic_nand};
use gsw_rs::params::{Params, SecurityLevel};
use rand::thread_rng;

let params = Params::toy();
let mut rng = thread_rng();
let (sk, pk) = gsw_keygen(&mut rng, &params);

// Encrypt bits
let ct0 = encrypt(&mut rng, &pk, 0);
let ct1 = encrypt(&mut rng, &pk, 1);

// Homomorphic XOR (addition mod 2)
let ct_xor = homomorphic_add(&params, &ct0, &ct1);
assert_eq!(decrypt(&sk, &ct_xor), 1);

// Homomorphic AND (multiplication)
let ct_and = homomorphic_mult(&params, &ct1, &ct1);
assert_eq!(decrypt(&sk, &ct_and), 1);

// Bootstrapping (requires evaluation key)
use gsw_rs::bootstrap::{bootstrap, gen_evaluation_key};
let ek = gen_evaluation_key(&mut rng, &sk, &pk);
let ct_noisy = homomorphic_mult(&params, &ct1, &ct1);
let ct_refreshed = bootstrap(&params, &ct_noisy, &ek);
assert_eq!(decrypt(&sk, &ct_refreshed), 1);
```

## Testing

```bash
cargo test --release
```

Tests cover encrypt/decrypt, homomorphic operations (both seeded and non-deterministic RNG), and bootstrapping.

## Parameters

- **Toy** — `q=2^20`, `n=8` — Fast, for development and testing
- **Low** — Higher security (~64-bit)
- **Medium** — Higher security (~128-bit)

## References

- Gentry, Sahai, Waters: "Homomorphic Encryption from Learning With Errors"
- [The GSW FHE Scheme](https://docs.sotazk.org/docs/gsw_fhe_scheme)
