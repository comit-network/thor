pub mod harness;

use crate::{MedianTime, PtlcSecret, TX_FEE};
use harness::{
    create_channels, init_bitcoind, init_cli, swap_beta_ptlc_bob, update_balances, FUND,
};

use bitcoin::Amount;

#[tokio::test]
async fn e2e_punish_publication_of_revoked_commit_transaction() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        mut a_channel,
        mut b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        time_lock,
        _,
    ) = create_channels(&bitcoind).await;

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let a_balance = FUND - payment;
    let b_balance = FUND + payment;

    update_balances(
        &mut a_channel,
        &mut b_channel,
        &mut a_transport,
        &mut b_transport,
        a_balance,
        b_balance,
        time_lock,
    )
    .await;

    // Alice attempts to cheat by publishing a revoked commit transaction.
    let signed_revoked_tx_c = a_channel.latest_revoked_signed_tx_c().unwrap().unwrap();
    a_wallet
        .0
        .send_raw_transaction(signed_revoked_tx_c.clone())
        .await
        .unwrap();

    // Bob sees the transaction and punishes Alice.
    b_channel
        .punish(&b_wallet, signed_revoked_tx_c)
        .await
        .unwrap();

    let a_balance_after_punish = a_wallet.balance().await.unwrap();
    let b_balance_after_punish = b_wallet.balance().await.unwrap();

    assert_eq!(
        a_balance_after_punish, a_balance_after_open,
        "Alice should get no money back after being punished"
    );
    assert_eq!(
        b_balance_after_punish,
        b_balance_after_open + FUND * 2 - Amount::from_sat(TX_FEE) * 2,
        "Bob should get all the money back after punishing Alice"
    );
}

#[tokio::test]
async fn bob_can_refund_ptlc_if_alice_holds_onto_secret_after_first_update() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        mut a_channel,
        mut b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        _time_lock,
        _tx_fee,
    ) = create_channels(&bitcoind).await;

    // This is the initial wallet amount (fund + buffer) less the fund amount less
    // the transaction fee to open the channel.
    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    let (alpha_absolute_expiry, ptlc_absolute_expiry, split_transaction_relative_expiry) = {
        let now = a_wallet.median_time().await.unwrap();

        let five_seconds = 5;
        let ptlc_absolute = now + five_seconds;
        let alpha_absolute = ptlc_absolute + five_seconds;

        let split_transaction_relative = 1;

        (alpha_absolute, ptlc_absolute, split_transaction_relative)
    };

    // Alice collaborates to add the PTLC to the channel, but does not reveal the
    // secret
    let add_ptlc_alice = a_channel.add_ptlc_redeemer(
        &mut a_transport,
        ptlc_amount,
        secret,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
    );

    let skip_final_update = false;
    let swap_beta_ptlc_bob = swap_beta_ptlc_bob(
        &mut b_channel,
        &mut b_transport,
        &b_wallet,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
        skip_final_update,
    );

    futures::future::try_join(add_ptlc_alice, swap_beta_ptlc_bob)
        .await
        .unwrap();

    let a_balance_after_close = a_wallet.0.balance().await.unwrap();
    let b_balance_after_close = b_wallet.0.balance().await.unwrap();

    // A `SplitTransaction` containing a PTLC output has 2 balance outputs and 1
    // PTLC output, for a total of 3
    let n_outputs_split_transaction = 3;

    // The fees are distributed evenly between the outputs.
    let fee_deduction_per_split_output =
        Amount::from_sat(TX_FEE + TX_FEE) / n_outputs_split_transaction;

    // Alice will just claim her balance output
    let a_split_transaction_fee = fee_deduction_per_split_output;

    // Bob will claim his balance output and refund the PTLC output
    let b_split_transaction_fee = fee_deduction_per_split_output * 2;

    // Additionally, Bob pays an extra `TX_FEE` to be able to refund the
    // PTLC output.
    let fee_deduction_for_ptlc_refund = Amount::from_sat(TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + FUND - a_split_transaction_fee,
        "Balance after closing channel should equal balance after opening plus PTLC amount,
         minus transaction fees"
    );

    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + FUND - b_split_transaction_fee - fee_deduction_for_ptlc_refund,
        "Balance after closing channel and refunding PTLC should equal balance after opening
         plus PTLC amount, minus transaction fees"
    );
}
