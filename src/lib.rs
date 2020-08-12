#![allow(non_snake_case, unused, unreachable_code)]

pub mod create;
mod keys;
mod signature;
mod transaction;
pub mod update;

use crate::keys::OwnershipPublicKey;
use bitcoin::Amount;

#[derive(Clone)]
pub struct ChannelBalance {
    a: (Amount, OwnershipPublicKey),
    b: (Amount, OwnershipPublicKey),
}
