use crate::context::{Ctx, Element, Exponent};
use crate::elgamal::Ciphertext;
use crate::zkp::{ChaumPedersen, Zkp};

pub fn get_coefficients<C: Ctx>(trustees: usize, threshold: u32, ctx: &C) -> Vec<C::X> { 
    let mut coefficients = vec![];

    for _ in 0..threshold {
        let coeff = ctx.rnd_exp();
        coefficients.push(coeff);
    }

    coefficients
}

fn eval_poly<C: Ctx>(trustee: usize, threshold: usize, coefficients: &[C::X], ctx: &C) -> C::X {
    let mut sum = coefficients[0].clone();
    let mut power = C::X::mul_identity();
    let trustee_exp = ctx.exp_from_u64(trustee as u64);

    for coefficient in coefficients.iter().take(threshold).skip(1) {
        power = power.mul(&trustee_exp).modulo(ctx.exp_modulus());
        sum = sum.add(&coefficient.mul(&power).modulo(ctx.exp_modulus()));
    }
    sum.modulo(ctx.exp_modulus())
}

fn compute_peer_share<C: Ctx>(target_trustee: usize, threshold: usize, coefficients: &[C::X], ctx: &C)-> C::X {
    // i + 1: trustees start at 1
    eval_poly(target_trustee + 1, threshold, &coefficients, ctx)
}

fn compute_secret_share<C: Ctx>(private_shares: &[C::X], trustees: usize, ctx: &C) -> C::X {
    let mut sum = C::X::add_identity();
    for i in 0..trustees {
        sum = sum.add(&private_shares[i]);
    }

    sum.modulo(ctx.exp_modulus())
}