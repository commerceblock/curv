/*
    Curv

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

use super::rand::rngs::OsRng;
use super::rand::RngCore;
use super::traits::{
    ConvertFrom, Converter, Modulo, NumberTests, Samplable, ZeroizeBN, EGCD, BitManipulation,
};
use num_bigint::BigInt as NumBigInt;
use num_bigint::{ModInverse, Sign};
pub use num_integer::Integer;
pub use num_traits::{Num, ToPrimitive, One, Zero, Pow, Signed};

use std::ptr;
use std::sync::atomic;
use std::convert::From;
use std::ops::BitOrAssign;
use std::ops::BitXorAssign;

pub type BigInt = NumBigInt;

impl ZeroizeBN for NumBigInt {
    fn zeroize_bn(&mut self) {
        unsafe { ptr::write_volatile(self, BigInt::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl Converter for NumBigInt {
    /// Sign ignored here
    fn to_vec(&self) -> Vec<u8> {
        let bytes: Vec<u8> = self.to_bytes_be().1;
        bytes
    }

    fn from_vec(value: &[u8]) -> NumBigInt {
        NumBigInt::from_bytes_be(Sign::Plus, value)
    }

    fn to_hex(&self) -> String {
        self.to_str_radix(super::HEX_RADIX.into())
    }

    fn from_hex(value: &str) -> NumBigInt {
        BigInt::from_str_radix(value, super::HEX_RADIX.into()).expect("Error in serialization")
    }
}

impl Modulo for NumBigInt {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.modpow(exponent, modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);

        let sub_op = a_m - b_m + modulus;
        sub_op.mod_floor(modulus)
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) + b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        a.mod_inverse(modulus).expect("Failed to invert")
    }
}

impl Samplable for NumBigInt {
    fn sample_below(upper: &Self) -> Self {
        assert!(*upper > NumBigInt::zero());

        let bits = upper.bits() as usize;
        loop {
            let n = Self::sample(bits);
            if n < *upper {
                return n;
            }
        }
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        lower + Self::sample_below(&(upper - lower))
    }

    fn strict_sample_range(lower: &Self, upper: &Self) -> Self {
        assert!(upper > lower);
        loop {
            let n = lower + Self::sample_below(&(upper - lower));
            if n > *lower && n < *upper {
                return n;
            }
        }
    }

    fn sample(bit_size: usize) -> Self {
        let mut rng = OsRng::new().unwrap();
        let bytes = (bit_size - 1) / 8 + 1;
        let mut buf: Vec<u8> = vec![0; bytes];
        rng.fill_bytes(&mut buf);
        let bn = Self::from_vec(&*buf);
        bn >> (bytes * 8 - bit_size)
    }

    fn strict_sample(bit_size: usize) -> Self {
        loop {
            let n = Self::sample(bit_size);
            if (n.bits() as usize) == bit_size {
                return n;
            }
        }
    }
}

impl NumberTests for NumBigInt {
    fn is_zero(me: &Self) -> bool {
        me.is_zero()
    }
    fn is_even(me: &Self) -> bool {
        me.is_multiple_of(&NumBigInt::from(2))
    }
    fn is_negative(me: &Self) -> bool {
        *me < NumBigInt::from(0)
    }
}

impl EGCD for NumBigInt {
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self) {
        let extgcd = a.extended_gcd_lcm(b);
        (extgcd.0.gcd, extgcd.0.x, extgcd.0.y)
    }
}


impl BitManipulation for BigInt {
    fn bit_length(self: &Self) -> usize {
        self.clone().to_str_radix(2).len()
    }
    fn set_bit(self: &mut Self, bit: usize, bit_val: bool) {
        let mask_bn = BigInt::from(1) << bit;
        if bit_val {
            // Set bit
            self.bitor_assign(mask_bn);   // OR to set bit
        } else {
            // Clear bit
            self.bitor_assign(mask_bn.clone());   // OR to set bit
            self.bitxor_assign(mask_bn);    // XOR to toggle bit
        }
    }

    fn test_bit(self: &Self, bit: usize) -> bool {
        let mask_bn = BigInt::from(1) << bit;
        if self == &(self.clone() | mask_bn) {
            return true;
        }
        false
    }
}

impl ConvertFrom<BigInt> for u64 {
    fn _from(x: &BigInt) -> u64 {
        x.to_u64().unwrap()
    }
}


#[cfg(test)]
mod tests {
    use super::Converter;
    use super::Modulo;
    use super::Samplable;
    use super::BigInt;
    use super::EGCD;

    use std::cmp;
    use std::convert::From;

    use crate::arithmetic::traits::{BitManipulation, ZeroizeBN};
    use num_traits::Zero;

    use floating_duration::TimeAsFloat;
    use std::time::Instant;

    #[allow(dead_code)]
    fn time_ops_add() {
        let n = 10000;
        let mut time: f64 = 0.0;
        for i in 0..n {
            let num1 = BigInt::sample(1024);
            let num2 = BigInt::sample(1024);
            let start = Instant::now();
            let _ = BigInt::mod_add(&num1, &num2, &BigInt::from(10));
            let elapsed = start.elapsed().as_fractional_micros();
            if i > 2 {
                time = time + elapsed;
            }
        }
        println!("time: {:?}", time / n as f64);
    }

    #[allow(dead_code)]
    fn time_ops_mul() {
        let n = 10000;
        let mut time: f64 = 0.0;
        for i in 0..n {
            let num1 = BigInt::sample(1024);
            let num2 = BigInt::sample(1024);
            let start = Instant::now();
            let _ = BigInt::mod_mul(&num1, &num2, &BigInt::from(10));
            let elapsed = start.elapsed().as_fractional_micros();
            if i > 2 {
                time = time + elapsed;
            }
        }
        println!("time: {:?}", time / n as f64);
    }

    #[allow(dead_code)]
    fn time_ops_pow() {
        let n = 10000;
        let mut time: f64 = 0.0;
        for i in 0..n {
            let num1 = BigInt::sample(1024);
            let num2 = BigInt::sample(1024);
            let start = Instant::now();
            let _ = BigInt::mod_pow(&num1, &num2, &BigInt::from(10));
            let elapsed = start.elapsed().as_fractional_micros();
            if i > 2 {
                time = time + elapsed;
            }
        }
        println!("time: {:?}", time / n as f64);
    }

    #[allow(dead_code)]
    fn time_ops_inv() {
        let n = 10000;
        let mut time: f64 = 0.0;
        for i in 0..n {
            let num1 = BigInt::sample(1024);
            let start = Instant::now();
            let _ = BigInt::mod_inv(&num1, &BigInt::from(10));
            let elapsed = start.elapsed().as_fractional_micros();
            if i > 2 {
                time = time + elapsed;
            }
        }
        println!("time: {:?}", time / n as f64);
    }

    #[test]
    fn egcd_test() {
        let num1 = BigInt::from(360);
        let num2 = BigInt::from(1290);
        assert_eq!(EGCD::egcd(&num1, &num2),
            (BigInt::from(30), BigInt::from(18), BigInt::from(-5)));
    }

    #[test]
    fn zeroize_test() {
        let bn10 = BigInt::from(10);
        let mut bn0 = bn10.clone();
        bn0.zeroize_bn();
        assert_eq!(bn0.clone()+bn10.clone(), bn10.clone());
        assert_eq!(bn0.clone()-bn10.clone(), -bn10.clone());
    }

    #[test]
    fn to_from_vec_test() {
        let bn_0 = BigInt::zero();
        let bn_0_vec = bn_0.to_vec();
        assert_eq!(BigInt::from_vec(&bn_0_vec), bn_0);

        let bn_rand = BigInt::sample_below(&BigInt::from(99999999));
        let bn_rand_vec = bn_rand.to_vec();
        assert_eq!(BigInt::from_vec(&bn_rand_vec), bn_rand);
    }

    #[test]
    #[should_panic]
    fn sample_below_zero_test() {
        BigInt::sample_below(&BigInt::from(-1));
    }

    #[test]
    fn sample_below_test() {
        let upper_bound = BigInt::from(10);

        for _ in 1..100 {
            let r = BigInt::sample_below(&upper_bound);
            assert!(r < upper_bound);
        }
    }

    #[test]
    #[should_panic]
    fn invalid_range_test() {
        BigInt::sample_range(&BigInt::from(10), &BigInt::from(9));
    }

    #[test]
    fn sample_range_test() {
        let upper_bound = BigInt::from(10);
        let lower_bound = BigInt::from(5);

        for _ in 1..100 {
            let r = BigInt::sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_range_test() {
        let len = 249;

        for _ in 1..100 {
            let a = BigInt::sample(len);
            let b = BigInt::sample(len);
            let lower_bound = cmp::min(a.clone(), b.clone());
            let upper_bound = cmp::max(a.clone(), b.clone());

            let r = BigInt::strict_sample_range(&lower_bound, &upper_bound);
            assert!(r < upper_bound && r >= lower_bound);
        }
    }

    #[test]
    fn strict_sample_test() {
        let len = 249;

        for _ in 1..100 {
            let a = BigInt::strict_sample(len);
            assert_eq!(a.bits() as usize, len);
        }
    }

    //test mod_sub: a-b mod n where a-b >0
    #[test]
    fn test_mod_sub_modulo() {
        let a = BigInt::from(10);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    //test mod_sub: a-b mod n where a-b <0
    #[test]
    fn test_mod_sub_negative_modulo() {
        let a = BigInt::from(5);
        let b = BigInt::from(10);
        let modulo = BigInt::from(3);
        let res = BigInt::from(1);
        assert_eq!(res, BigInt::mod_sub(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_mul() {
        let a = BigInt::from(4);
        let b = BigInt::from(5);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_mul(&a, &b, &modulo));
    }

    #[test]
    fn test_mod_pow() {
        let a = BigInt::from(2);
        let b = BigInt::from(3);
        let modulo = BigInt::from(3);
        let res = BigInt::from(2);
        assert_eq!(res, BigInt::mod_pow(&a, &b, &modulo));
    }

    #[test]
    fn test_to_hex() {
        let b = BigInt::from(11);
        assert_eq!("b", b.to_hex());
    }

    #[test]
    fn test_from_hex() {
        let a = BigInt::from(11);
        assert_eq!(BigInt::from_hex(&a.to_hex()), a);
    }

    #[test]
    fn bit_length_test() {
        assert_eq!(BigInt::from(1).bit_length(), 1);
        assert_eq!(BigInt::from(2).bit_length(), 2);
        assert_eq!(BigInt::from(584).bit_length(), 10);
    }

    #[test]
    fn bit_manipulation_test() {
        let bn8 = BigInt::from(8);
        let mut bn_set_bit_1 = bn8.clone();
        bn_set_bit_1.set_bit(3, true);
        assert_eq!(bn8, bn_set_bit_1); // set bit already set

        let mut bn_set_bit_2 = bn8.clone();
        bn_set_bit_2.set_bit(2, true);
        assert_eq!(BigInt::from(12), bn_set_bit_2); // set bit 2

        let mut bn_set_bit_10 = bn8.clone();
        bn_set_bit_10.set_bit(10, true);
        assert_eq!(BigInt::from(1032), bn_set_bit_10); // set bit 10

        // unset bit 10
        bn_set_bit_10.set_bit(10, false);
        assert_eq!(bn8, bn_set_bit_10);

        // test bit set
        assert_eq!(bn8.test_bit(10), false);
        assert_eq!(bn8.test_bit(3), true);
    }
}
