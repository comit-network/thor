#![allow(non_snake_case, unused, unreachable_code)]

pub mod create;
mod keys;
mod signature;
mod transaction;

use crate::keys::PublicKey;
use bitcoin::Amount;

pub struct ChannelState {
    a: (Amount, PublicKey),
    b: (Amount, PublicKey),
}
