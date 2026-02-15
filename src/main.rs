//! Demo: GSW FHE with bootstrapping.

use gsw_rs::bootstrap::{bootstrap, gen_evaluation_key};
use gsw_rs::gadget::powers_of_2;
use gsw_rs::params::{Params, SecurityLevel};
use gsw_rs::{decrypt, encrypt, gsw_keygen, homomorphic_add, homomorphic_mult, homomorphic_nand};
use rand::thread_rng;

fn main() {
    println!("GSW Lattice FHE Implementation - Demo\n");

    let params = Params::new(SecurityLevel::Toy);
    // let params = Params::new(SecurityLevel::Low);
    // let params = Params::new(SecurityLevel::Medium);
    println!(
        "Parameters: n={}, q=2^{}, N={}",
        params.n, params.l, params.n_expanded
    );

    let mut rng = thread_rng();

    // Key generation
    println!("\n--- Key Generation ---");
    let (sk, pk) = gsw_keygen(&mut rng, &params);
    println!("Secret key length: {}", sk.s.len());
    println!("Public key matrix: {}x{}", pk.a.len(), pk.a[0].len());

    // Basic encryption/decryption
    println!("\n--- Basic Encryption ---");
    for bit in [0u8, 1u8] {
        let ct = encrypt(&mut rng, &pk, bit);
        let dec = decrypt(&sk, &ct);
        println!(
            "Encrypt({}) -> Decrypt -> {} {}",
            bit,
            dec,
            if dec == bit { "✓" } else { "✗" }
        );
    }

    // Homomorphic operations
    println!("\n--- Homomorphic Operations ---");

    let ct0 = encrypt(&mut rng, &pk, 0);
    let ct1 = encrypt(&mut rng, &pk, 1);

    // XOR (addition mod 2): 0+0=0, 0+1=1, 1+0=1, 1+1=0
    let ct_xor_00 = homomorphic_add(&params, &ct0, &ct0);
    let ct_xor_01 = homomorphic_add(&params, &ct0, &ct1);
    let ct_xor_11 = homomorphic_add(&params, &ct1, &ct1);
    println!(
        "0 XOR 0 = {} (expected 0) {}",
        decrypt(&sk, &ct_xor_00),
        if decrypt(&sk, &ct_xor_00) == 0 {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "0 XOR 1 = {} (expected 1) {}",
        decrypt(&sk, &ct_xor_01),
        if decrypt(&sk, &ct_xor_01) == 1 {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "1 XOR 1 = {} (expected 0) {}",
        decrypt(&sk, &ct_xor_11),
        if decrypt(&sk, &ct_xor_11) == 0 {
            "✓"
        } else {
            "✗"
        }
    );

    // AND (multiplication): 0*0=0, 0*1=0, 1*0=0, 1*1=1
    let ct_and_00 = homomorphic_mult(&params, &ct0, &ct0);
    let ct_and_01 = homomorphic_mult(&params, &ct0, &ct1);
    let ct_and_11 = homomorphic_mult(&params, &ct1, &ct1);
    println!(
        "0 AND 0 = {} (expected 0) {}",
        decrypt(&sk, &ct_and_00),
        if decrypt(&sk, &ct_and_00) == 0 {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "0 AND 1 = {} (expected 0) {}",
        decrypt(&sk, &ct_and_01),
        if decrypt(&sk, &ct_and_01) == 0 {
            "✓"
        } else {
            "✗"
        }
    );
    println!(
        "1 AND 1 = {} (expected 1) {}",
        decrypt(&sk, &ct_and_11),
        if decrypt(&sk, &ct_and_11) == 1 {
            "✓"
        } else {
            "✗"
        }
    );

    // NAND
    let ct_nand = homomorphic_nand(&params, &ct1, &ct1);
    println!(
        "1 NAND 1 = {} (expected 0) {}",
        decrypt(&sk, &ct_nand),
        if decrypt(&sk, &ct_nand) == 0 {
            "✓"
        } else {
            "✗"
        }
    );

    // 0 NAND 0 = 1
    let ct_nand_00 = homomorphic_nand(&params, &ct0, &ct0);
    println!(
        "0 NAND 0 = {} (expected 1) {}",
        decrypt(&sk, &ct_nand_00),
        if decrypt(&sk, &ct_nand_00) == 1 {
            "✓"
        } else {
            "✗"
        }
    );

    // 1 NAND 0 = 1
    let ct_nand_10 = homomorphic_nand(&params, &ct1, &ct0);
    println!(
        "1 NAND 0 = {} (expected 1) {}",
        decrypt(&sk, &ct_nand_10),
        if decrypt(&sk, &ct_nand_10) == 1 {
            "✓"
        } else {
            "✗"
        }
    );

    // Bootstrapping
    println!("\n--- Bootstrapping ---");
    println!("Generating evaluation key (encrypted secret key bits)...");
    let ek = gen_evaluation_key(&mut rng, &sk, &pk);
    println!("Evaluation key: {} encrypted bits", ek.encryptions.len());

    println!("Bootstrapping a ciphertext...");

    // timing the bootstrapping

    let ct_to_bootstrap = homomorphic_mult(&params, &ct1, &ct1);
    let msg_before = decrypt(&sk, &ct_to_bootstrap);
    let val_clear = gsw_rs::bootstrap::decrypt_linear_part_clear(&sk, &ct_to_bootstrap);
    let scale = powers_of_2(&sk.s, &params)[params.l - 1];
    let true_msg = 1u8; // Enc(1)*Enc(1) = Enc(1)
    println!(
        "  Input: val={}, scale={}, noisy_decrypt={}",
        val_clear, scale, msg_before
    );
    let start_time = std::time::Instant::now();
    let ct_bootstrapped = bootstrap(&params, &ct_to_bootstrap, &ek);
    let end_time = std::time::Instant::now();
    let duration = end_time.duration_since(start_time);
    println!("Time taken to bootstrap the ciphertext: {:?}", duration);
    let msg_after = decrypt(&sk, &ct_bootstrapped);
    let val_bootstrap = gsw_rs::bootstrap::decrypt_linear_part_clear(&sk, &ct_bootstrapped);
    println!(
        "  Bootstrap output: val={}, decrypt={}",
        val_bootstrap, msg_after
    );
    println!(
        "  Bootstrap {} (noisy had decrypt={}, true msg={})",
        if msg_after == true_msg {
            "correctly refreshed!"
        } else {
            "decrypt mismatch"
        },
        msg_before,
        true_msg
    );

    println!("\n--- Summary ---");
    println!("GSW FHE implementation complete with:");
    println!("  - LWE key generation");
    println!("  - Bit encryption/decryption");
    println!("  - Homomorphic XOR (addition), AND (multiplication), NAND");
    println!("  - Bootstrapping (homomorphic decryption linear part)");
}
