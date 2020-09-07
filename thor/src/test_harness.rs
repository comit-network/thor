use crate::{Balance, Channel, MedianTime, PtlcPoint};
use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use futures::future;
use genawaiter::GeneratorState;
use spectral::prelude::*;
use testcontainers::clients::Cli;

mod transport;
mod wallet;

pub use transport::{make_transports, Transport};
pub use wallet::{make_wallets, Wallet};

// Alice and Bob both fund the channel with this much.
pub const FUND: Amount = Amount::ONE_BTC;

pub async fn create_channels(
    bitcoind: &Bitcoind<'_>,
) -> (
    Channel,
    Channel,
    Transport,
    Transport,
    Wallet,
    Wallet,
    u32,
    Amount,
) {
    let (mut a_transport, mut b_transport) = make_transports();
    let (a_balance, b_balance) = generate_balances(FUND);
    let (a_wallet, b_wallet) = make_wallets(bitcoind, FUND)
        .await
        .expect("failed to make wallets");
    let time_lock = 1;

    let initial_balance = a_wallet.balance().await.unwrap();

    let a_create = Channel::create(&mut a_transport, &a_wallet, a_balance, time_lock);
    let b_create = Channel::create(&mut b_transport, &b_wallet, b_balance, time_lock);

    let (a_channel, b_channel) = future::try_join(a_create, b_create)
        .await
        .expect("failed to create channels");

    assert_channel_balances(&a_channel, &b_channel, FUND, FUND);

    let final_balance = a_wallet.balance().await.unwrap();
    let tx_fee = initial_balance - final_balance - FUND;

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

pub struct SwapExpiries {
    pub alpha_absolute: u32,
    pub ptlc_absolute: u32,
    pub split_transaction_relative: u32,
}

pub async fn generate_expiries<C>(connector: &C) -> anyhow::Result<SwapExpiries>
where
    C: MedianTime,
{
    let now = connector.median_time().await?;
    let twelve_hours = 12 * 60 * 60;

    let ptlc_absolute = now + twelve_hours;
    let alpha_absolute = ptlc_absolute + twelve_hours;

    let split_transaction_relative = 1;

    Ok(SwapExpiries {
        alpha_absolute,
        ptlc_absolute,
        split_transaction_relative,
    })
}

/// Wrapper around the `Channel::swap_beta_ptlc_bob` API. It allows to configure
/// if Bob will run a final update so that Alice can get the PTLC assigned to
/// herself.
#[allow(clippy::too_many_arguments)]
pub async fn swap_beta_ptlc_bob(
    channel: &mut Channel,
    transport: &mut Transport,
    wallet: &Wallet,
    ptlc_amount: Amount,
    point: PtlcPoint,
    alpha_absolute_expiry: u32,
    TX_s_time_lock: u32,
    ptlc_redeem_time_lock: u32,
    skip_update: bool,
) -> anyhow::Result<()> {
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
