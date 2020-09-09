use bitcoin::Amount;
use thor::Balance;

mod transport;
mod wallet;

pub use transport::{make_transports, Transport};
pub use wallet::{make_wallets, Wallet};

pub fn generate_balances(fund_amount: Amount) -> (Balance, Balance) {
    _generate_balances(fund_amount, fund_amount)
}

fn _generate_balances(a_fund_amount: Amount, b_fund_amount: Amount) -> (Balance, Balance) {
    let a_balance = Balance {
        ours: a_fund_amount,
        theirs: b_fund_amount,
    };

    let b_balance = Balance {
        ours: b_fund_amount,
        theirs: a_fund_amount,
    };

    (a_balance, b_balance)
}
