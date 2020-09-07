use crate::{
    test_harness::{create_channels, init_bitcoind, init_cli, swap_beta_ptlc_bob, FUND},
    MedianTime, PtlcSecret, TX_FEE,
};
use bitcoin::Amount;

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

    let hold_secret = true;
    let swap_beta_ptlc_alice = a_channel.swap_beta_ptlc_alice(
        &mut a_transport,
        &a_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
        hold_secret,
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

    futures::future::try_join(swap_beta_ptlc_alice, swap_beta_ptlc_bob)
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
