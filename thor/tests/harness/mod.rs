use bitcoin::Amount;
use thor::{Balance, MedianTime};

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
