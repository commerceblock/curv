
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

#![no_std]


#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]
#[cfg(all(feature = "mesalock_sgx", feature = "std", not(target_env = "sgx")))]
extern crate sgx_tstd as std;

#[cfg(all(feature = "mesalock_sgx", target_env = "sgx"))]
extern crate std;

#[cfg(feature = "bigint")]
extern crate num_bigint_dig as num_bigint;
#[cfg(feature = "serde")]
extern crate serde;

extern crate num_integer;
extern crate num_traits;

use core::cmp;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Add, Div, Mul, Neg, Rem, Sub};
use core::str::FromStr;
#[cfg(feature = "std")]
use std::error::Error;

//#[cfg(feature = "bigint")]
//use num_bigint::{BigInt, BigUint, Sign};

use num_integer::Integer;
use num_traits::float::FloatCore;
use num_traits::{
    Bounded, CheckedAdd, CheckedDiv, CheckedMul, CheckedSub, FromPrimitive, Inv, Num, NumCast, One,
    Pow, Signed, Zero,
};

#[cfg(feature = "bigint")]
pub fn test_bigint() {
    let one: BigInt = One::one();
    let zero: BigInt = Zero::zero();
    let modulus = &BigInt::from(2);
    let result = (one.mod_floor(modulus) * zero.mod_floor(modulus)).mod_floor(modulus);
    ()
}


//extern crate sgx_types;
//#[cfg(not(target_env = "sgx"))]
//#[macro_use]
//extern crate sgx_tstd as std;
//extern crate sgx_rand;

#[cfg(feature = "ec_secp256k1")]
extern crate secp256k1;

//use sgx_types::*;

//use std::backtrace::{self, PrintFormat};

//extern crate serde_derive;


//#[cfg(feature = "ecc")]
//pub mod elliptic;


//#[cfg(feature = "ec_secp256k1")]
//mod secp256k1instance {
//    pub use crate::elliptic::curves::secp256_k1::FE;
//    pub use crate::elliptic::curves::secp256_k1::GE;
//    pub use crate::elliptic::curves::secp256_k1::PK;
//    pub use crate::elliptic::curves::secp256_k1::SK;
//}
 

//#[cfg(feature = "ec_secp256k1")]
//pub use self::secp256k1instance::*;


#[cfg(feature = "ecc-sgx")]
pub mod elliptic;

/*
#[cfg(feature = "ec_secp256k1")]
pub use crate::enclave;
 */

#[cfg(feature = "ec_ristretto")]
mod curveristrettoinstance {
    pub use crate::elliptic::curves::curve_ristretto::FE;
    pub use crate::elliptic::curves::curve_ristretto::GE;
    pub use crate::elliptic::curves::curve_ristretto::PK;
    pub use crate::elliptic::curves::curve_ristretto::SK;
}

#[cfg(feature = "ec_ristretto")]
pub use self::curveristrettoinstance::*;

#[cfg(feature = "ec_ed25519")]
mod ed25519instance {
    pub use crate::elliptic::curves::ed25519::FE;
    pub use crate::elliptic::curves::ed25519::GE;
    pub use crate::elliptic::curves::ed25519::PK;
    pub use crate::elliptic::curves::ed25519::SK;
}

#[cfg(feature = "ec_ed25519")]
pub use self::ed25519instance::*;

#[cfg(feature = "ec_jubjub")]
mod jubjubinstance {
    pub use crate::elliptic::curves::curve_jubjub::FE;
    pub use crate::elliptic::curves::curve_jubjub::GE;
    pub use crate::elliptic::curves::curve_jubjub::PK;
    pub use crate::elliptic::curves::curve_jubjub::SK;
}

#[cfg(feature = "ec_jubjub")]
pub use self::jubjubinstance::*;

#[cfg(feature = "ec_bls12_381")]
mod bls12_381_instance {
    pub use crate::elliptic::curves::bls12_381::FE;
    pub use crate::elliptic::curves::bls12_381::GE;
    pub use crate::elliptic::curves::bls12_381::PK;
    pub use crate::elliptic::curves::bls12_381::SK;
}

#[cfg(feature = "ec_bls12_381")]
pub use self::bls12_381_instance::*;

#[cfg(feature = "rust-gmp")]
pub mod arithmetic;
#[cfg(feature = "rust-gmp")]
pub use crate::arithmetic::big_gmp::BigInt;

#[cfg(feature = "ecc")]
pub mod cryptographic_primitives;


#[cfg(feature = "rust_gmp_sgx")]
pub mod arithmetic_sgx;
#[cfg(feature = "rust_gmp_sgx")]
pub use crate::arithmetic_sgx::big_num::BigInt;

#[cfg(feature = "ecc-sgx")]
pub mod cryptographic_primitives_sgx;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

//#[cfg(test)]
//mod tests {
//    use super::*;
    
    
    /*
    /// Converts a float into a rational number.                                                                                                                                                                                                                                          
    pub fn from_float<T: FloatCore>(f: T) -> Option<BigRational> {
        if !f.is_finite() {
            return None;
        }
        let (mantissa, exponent, sign) = f.integer_decode();
        let bigint_sign = if sign == 1 { Sign::Plus } else { Sign::Minus };
        if exponent < 0 {
            let one: BigInt = One::one();
            let denom: BigInt = one << ((-exponent) as usize);
            let numer: BigUint = FromPrimitive::from_u64(mantissa).unwrap();
            Some(Ratio::new(BigInt::from_biguint(bigint_sign, numer), denom))
        } else {
            let mut numer: BigUint = FromPrimitive::from_u64(mantissa).unwrap();
            numer = numer << (exponent as usize);
            Some(Ratio::from_integer(BigInt::from_biguint(
                bigint_sign,
                numer,
            )))
        }
    }
     */
//}

    

