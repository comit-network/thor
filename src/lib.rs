//! # Thor
//!
//! A proof of concept of the paper: `Generalized Bitcoin-compatible channels` on top of Bitcoin.
//!
//! # Examples
//!
//! ## Open a channel
//!
//! ```rust
//! use bitcoin_harness::{Bitcoind, bitcoind_rpc, Client, Wallet};
//!
//! # #[tokio::main]
//! # async fn main() {
//! // Setting up a Bitcoin regtest environment
//! let tc_client = testcontainers::clients::Cli::default();
//! let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
//! let client = Client::new(bitcoind.node_url.clone());
//! bitcoind.init(5).await.unwrap();
//!
//! let alice_wallet = Wallet::new("alice_wallet", bitcoind.node_url.clone()).await.unwrap();
//! {
//!     let address = alice_wallet.new_address().await.unwrap();
//!     let amount = bitcoin::Amount::from_btc(3.0).unwrap();
//!     bitcoind.mint(address, amount).await.unwrap();
//! }
//!
//! let bob_wallet = Wallet::new("alice_wallet", bitcoind.node_url.clone()).await.unwrap();
//! {
//!     let address = bob_wallet.new_address().await.unwrap();
//!     let amount = bitcoin::Amount::from_btc(3.0).unwrap();
//!     bitcoind.mint(address, amount).await.unwrap();
//! }
//!
//! # }
//! ```

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
