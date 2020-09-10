use crate::{Balance, Channel, MedianTime, PtlcPoint};
use anyhow::Result;
use bitcoin::Amount;
use genawaiter::GeneratorState;

mod transport;
mod wallet;

pub use transport::{make_transports, Transport};
pub use wallet::{make_wallets, Wallet};

pub fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new()
        .enable_all()
        .threaded_scheduler()
        .thread_stack_size(1024 * 1024 * 8)
        .build()
        .unwrap()
}

pub fn generate_balances(fund_amount_alice: Amount, fund_amount_bob: Amount) -> (Balance, Balance) {
    let balance_alice = Balance {
        ours: fund_amount_alice,
        theirs: fund_amount_bob,
    };

    let balance_bob = Balance {
        ours: fund_amount_bob,
        theirs: fund_amount_alice,
    };

    (balance_alice, balance_bob)
}

#[derive(Copy, Clone, Debug)]
pub struct SwapExpiries {
    pub alpha_absolute: u32,
    pub ptlc_absolute: u32,
    pub split_transaction_relative: u32,
}

pub async fn generate_expiries<C>(connector: &C) -> Result<SwapExpiries>
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
    tx_s_time_lock: u32,
    ptlc_redeem_time_lock: u32,
    skip_update: bool,
) -> Result<()> {
    let mut swap_beta_ptlc_bob = channel.swap_beta_ptlc_bob(
        transport,
        wallet,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        tx_s_time_lock,
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
