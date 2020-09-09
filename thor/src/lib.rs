#![warn(
    unused_extern_crates,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2018_idioms,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::fallible_impl_from,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::dbg_macro
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used))]
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

#[cfg(feature = "serde")]
pub(crate) mod serde;

mod channel;
mod keys;
mod signature;
mod transaction;

#[cfg(test)]
mod public_api_tests;
#[cfg(test)]
mod test_harness;

pub use ::bitcoin;
pub use channel::*;
pub use keys::{PtlcPoint, PtlcSecret};

use bitcoin::Amount;
use enum_as_inner::EnumAsInner;
use keys::OwnershipPublicKey;

// TODO: We should handle fees dynamically

/// Flat fee used for all transactions involved in the protocol, in satoshi.
pub const TX_FEE: u64 = 10_000;

#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Clone)]
pub struct Ptlc {
    #[cfg_attr(
        feature = "serde",
        serde(with = "bitcoin::util::amount::serde::as_sat")
    )]
    amount: Amount,
    X_funder: OwnershipPublicKey,
    X_redeemer: OwnershipPublicKey,
    role: Role,
    refund_time_lock: u32,
}

impl Ptlc {
    pub fn point(&self) -> PtlcPoint {
        match &self.role {
            Role::Alice { secret } => secret.point(),
            Role::Bob { point } => point.clone(),
        }
    }
}

/// Role in an atomic swap.
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[derive(Debug, Clone, EnumAsInner)]
pub enum Role {
    Alice { secret: PtlcSecret },
    Bob { point: PtlcPoint },
}
