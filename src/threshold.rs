use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::Ciphertext;
use crate::zkp::{ChaumPedersen, Zkp};

pub fn gen_coefficients<C: Ctx>(
    _trustees: usize,
    threshold: u32,
    ctx: &C,
) -> (Vec<C::X>, Vec<C::E>) {
    let mut coefficients = vec![];
    let mut commitments = vec![];

    for _ in 0..threshold {
        let coeff = ctx.rnd_exp();
        let commitment = ctx.gmod_pow(&coeff);
        coefficients.push(coeff);
        commitments.push(commitment);
    }

    (coefficients, commitments)
}

pub fn eval_poly<C: Ctx>(trustee: usize, threshold: usize, coefficients: &[C::X], ctx: &C) -> C::X {
    let mut sum = coefficients[0].clone();
    let mut power = C::X::mul_identity();
    let trustee_exp = ctx.exp_from_u64(trustee as u64);

    for coefficient in coefficients.iter().take(threshold).skip(1) {
        power = power.mul(&trustee_exp).modulo(ctx.exp_modulus());
        sum = sum.add(&coefficient.mul(&power).modulo(ctx.exp_modulus()));
    }
    sum.modulo(ctx.exp_modulus())
}

pub fn compute_peer_share<C: Ctx>(
    target_trustee: usize,
    threshold: usize,
    coefficients: &[C::X],
    ctx: &C,
) -> C::X {
    // i + 1: trustees start at 1
    eval_poly(target_trustee + 1, threshold, coefficients, ctx)
}

pub fn verification_key_factor<C: Ctx>(
    sender_commitments: &[C::E],
    threshold: usize,
    receiver_trustee: usize,
    ctx: &C,
) -> C::E {
    let mut accum = C::E::mul_identity();
    // trustees start at 1
    let t = receiver_trustee + 1;
    for (i, commitment) in sender_commitments.iter().enumerate().take(threshold) {
        let power = t.pow(i as u32);
        let power_element = ctx.exp_from_u64(power as u64);

        accum = accum
            .mul(&commitment.mod_pow(&power_element, ctx.modulus()))
            .modulo(ctx.modulus());
    }

    accum
}

pub fn decryption_factor<C: Ctx>(
    c: &Ciphertext<C>,
    share: &C::X,
    v_key: &C::E,
    label: &[u8],
    ctx: C,
) -> (C::E, ChaumPedersen<C>) {
    let zkp = Zkp::new(&ctx);
    let factor = c.gr.mod_pow(share, ctx.modulus());
    let proof = zkp.decryption_proof(share, v_key, &factor, &c.mhr, &c.gr, label);
    // let ok = zkp.decryption_verify(&v_key, &factor, None, &c.mhr, &c.gr, &proof, label);
    // assert!(ok);
    (factor, proof)
}

pub fn lagrange<C: Ctx>(trustee: usize, present: &[usize], ctx: &C) -> C::X {
    let mut numerator = C::X::mul_identity();
    let mut denominator = C::X::mul_identity();
    let trustee_exp = ctx.exp_from_u64(trustee as u64);

    for p in present {
        if *p == trustee {
            continue;
        }
        let present_exp = ctx.exp_from_u64(*p as u64);
        // we add exp_modulus to avoid calculating a modulus with negative numbers
        // whose behaviour can be implementation specific (also, the num_bigint backend does not support it)
        let diff_exp = present_exp
            .add(ctx.exp_modulus())
            .sub(&trustee_exp)
            .modulo(ctx.exp_modulus());

        numerator = numerator.mul(&present_exp).modulo(ctx.exp_modulus());
        denominator = denominator.mul(&diff_exp).modulo(ctx.exp_modulus());
    }

    numerator.div(&denominator, ctx.exp_modulus())
}
