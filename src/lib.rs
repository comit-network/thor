#![allow(non_snake_case)]

pub mod create;
mod keys;
mod transaction;

use crate::keys::PublicKey;
use bitcoin::Amount;

pub struct ChannelState {
    party_0: (Amount, PublicKey),
    party_1: (Amount, PublicKey),
}
