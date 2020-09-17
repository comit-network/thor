//! This module is a copy of the code over in `thor/tests/harness/` with the
//! following changes:
//! - Use `harness.rs` instead of `mod.rs`
//! - Remove unused code: `SwapExpiries` and `generate_expiries`.
//!
//! The reason we duplicate the test harness is because we want the integration
//! tests to remain outside of this crate in order to enforce usage of the
//! public API. Also we would like to write tests that mimic a malicious actor
//! on one side of the channel, this is not possible with the public API so we
//! put those tests inside the `channel` module.

// If you modify this file please also modify the other harness files in
// `thor/tests/harness`
//

use crate::{
    channel::{ReceiveMessage, SendMessage},
    Balance, Channel, Message, PtlcPoint,
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use futures::{
    channel::{
        mpsc,
        mpsc::{Receiver, Sender},
    },
    future, SinkExt, StreamExt,
};
use genawaiter::GeneratorState;
use spectral::prelude::*;
use testcontainers::clients::Cli;

mod wallet;
mod monero;

pub use wallet::{make_bitcoin_wallets, BitcoinWallet};
use crate::channel::tests::harness::monero::Monero;

// Alice and Bob both fund the channel with this much.
pub const BTC_FUND: Amount = Amount::ONE_BTC;

// Alice and Bob both fund the channel with this much.
pub const XMR_FUND: u64 = 100;


pub async fn create_channels(
    bitcoind: &Bitcoind<'_>,
) -> (
    Channel,
    Channel,
    Transport,
    Transport,
    BitcoinWallet,
    BitcoinWallet,
    u32,
    Amount,
) {
    let (mut a_transport, mut b_transport) = make_transports();
    let (a_balance, b_balance) = generate_balances(BTC_FUND);
    let (a_wallet, b_wallet) = make_bitcoin_wallets(bitcoind, BTC_FUND)
        .await
        .expect("failed to make wallets");
    let time_lock = 1;

    let initial_balance = a_wallet.balance().await.unwrap();

    let a_create = Channel::create(&mut a_transport, &a_wallet, a_balance, time_lock);
    let b_create = Channel::create(&mut b_transport, &b_wallet, b_balance, time_lock);

    let (a_channel, b_channel) = future::try_join(a_create, b_create)
        .await
        .expect("failed to create channels");

    assert_channel_balances(&a_channel, &b_channel, BTC_FUND, BTC_FUND);

    let final_balance = a_wallet.balance().await.unwrap();
    let tx_fee = initial_balance - final_balance - BTC_FUND;

    (
        a_channel,
        b_channel,
        a_transport,
        b_transport,
        a_wallet,
        b_wallet,
        time_lock,
        tx_fee,
    )
}


pub async fn create_btc_xmr_channels(
    bitcoind: &Bitcoind<'_>,
    monero: &Monero,
) -> (
    Channel,
    Channel,
    Transport,
    Transport,
    BitcoinWallet,
    BitcoinWallet,
    u32,
    Amount,
) {
    let (mut a_transport, mut b_transport) = make_transports();
    let (a_balance, b_balance) = generate_balances(BTC_FUND);
    let (a_wallet, b_wallet) = make_bitcoin_wallets(bitcoind, BTC_FUND)
        .await
        .expect("failed to make wallets");
    let time_lock = 1;

    let initial_balance = a_wallet.balance().await.unwrap();

    let a_create = Channel::create(&mut a_transport, &a_wallet, a_balance, time_lock);
    let b_create = Channel::create(&mut b_transport, &b_wallet, b_balance, time_lock);

    let (a_channel, b_channel) = future::try_join(a_create, b_create)
        .await
        .expect("failed to create channels");

    assert_channel_balances(&a_channel, &b_channel, BTC_FUND, BTC_FUND);

    let final_balance = a_wallet.balance().await.unwrap();
    let tx_fee = initial_balance - final_balance - BTC_FUND;

    (
        a_channel,
        b_channel,
        a_transport,
        b_transport,
        a_wallet,
        b_wallet,
        time_lock,
        tx_fee,
    )
}

// TODO: Convert this to a macro because line information for source of failure
// is lost when we use this function. Verify macro solves this problem.
pub fn assert_channel_balances(
    a_channel: &Channel,
    b_channel: &Channel,
    a_balance: Amount,
    b_balance: Amount,
) {
    assert_that!(a_channel.balance().ours).is_equal_to(a_balance);
    assert_that!(a_channel.balance().theirs).is_equal_to(b_balance);

    assert_that!(b_channel.balance().ours).is_equal_to(b_balance);
    assert_that!(b_channel.balance().theirs).is_equal_to(a_balance);
}

pub fn init_cli() -> Cli {
    Cli::default()
}

pub async fn init_bitcoind(tc_client: &Cli) -> Bitcoind<'_> {
    let bitcoind = Bitcoind::new(tc_client, "0.19.1").expect("failed to create bitcoind");
    let _ = bitcoind.init(5).await;

    bitcoind
}

pub async fn update_balances(
    a_channel: &mut Channel,
    b_channel: &mut Channel,
    a_transport: &mut Transport,
    b_transport: &mut Transport,
    a_balance: Amount,
    b_balance: Amount,
    time_lock: u32,
) {
    let a_update = a_channel.update_balance(
        a_transport,
        Balance {
            ours: a_balance,
            theirs: b_balance,
        },
        time_lock,
    );
    let b_update = b_channel.update_balance(
        b_transport,
        Balance {
            ours: b_balance,
            theirs: a_balance,
        },
        time_lock,
    );

    future::try_join(a_update, b_update)
        .await
        .expect("update failed");
}

pub fn generate_balances(fund_amount: Amount) -> (Balance, Balance) {
    let a_balance = Balance {
        ours: fund_amount,
        theirs: fund_amount,
    };

    let b_balance = Balance {
        ours: fund_amount,
        theirs: fund_amount,
    };
    (a_balance, b_balance)
}

/// Wrapper around the `Channel::swap_beta_ptlc_bob` API. It allows to configure
/// if Bob will run a final update so that Alice can get the PTLC assigned to
/// herself.
#[allow(clippy::too_many_arguments)]
pub async fn swap_beta_ptlc_bob(
    channel: &mut Channel,
    transport: &mut Transport,
    wallet: &BitcoinWallet,
    ptlc_amount: Amount,
    point: PtlcPoint,
    alpha_absolute_expiry: u32,
    TX_s_time_lock: u32,
    ptlc_redeem_time_lock: u32,
    skip_update: bool,
) -> Result<()> {
    let mut swap_beta_ptlc_bob = channel.swap_beta_ptlc_bob(
        transport,
        wallet,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        TX_s_time_lock,
        ptlc_redeem_time_lock,
    );

    match swap_beta_ptlc_bob.async_resume().await {
        GeneratorState::Yielded(_secret) => {
            // TODO: Redeem alpha asset

            if skip_update {
                return Ok(());
            }

            swap_beta_ptlc_bob.async_resume().await;
        }
        GeneratorState::Complete(Err(e)) => panic!("{}", e),
        // Alice does not reveal the secret in time, so Bob has refunded
        GeneratorState::Complete(Ok(())) => {}
    }

    Ok(())
}

/// Create two mock `Transport`s which mimic a peer to peer connection between
/// two parties, allowing them to send and receive `thor::Message`s.
pub fn make_transports() -> (Transport, Transport) {
    let (a_sender, b_receiver) = mpsc::channel(5);
    let (b_sender, a_receiver) = mpsc::channel(5);

    let a_transport = Transport {
        sender: a_sender,
        receiver: a_receiver,
    };

    let b_transport = Transport {
        sender: b_sender,
        receiver: b_receiver,
    };

    (a_transport, b_transport)
}

#[derive(Debug)]
pub struct Transport {
    // Using String instead of `Message` implicitly tests the `use-serde` feature.
    sender: Sender<String>,
    receiver: Receiver<String>,
}

#[async_trait]
impl SendMessage for Transport {
    async fn send_message(&mut self, message: Message) -> Result<()> {
        let str = serde_json::to_string(&message).context("failed to encode message")?;
        self.sender
            .send(str)
            .await
            .map_err(|_| anyhow!("failed to send message"))
    }
}

#[async_trait]
impl ReceiveMessage for Transport {
    async fn receive_message(&mut self) -> Result<Message> {
        let str = self
            .receiver
            .next()
            .await
            .ok_or_else(|| anyhow!("failed to receive message"))?;
        let message = serde_json::from_str(&str).context("failed to decode message")?;
        Ok(message)
    }
}
