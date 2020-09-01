use bitcoin::Amount;
use thor::Balance;

mod transport;
mod wallet;

pub use transport::{make_transports, Transport};
pub use wallet::make_wallets;

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
