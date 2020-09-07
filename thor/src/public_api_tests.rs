#![allow(non_snake_case)]

use crate::{
    test_harness::{
        assert_channel_balances, create_channels, generate_expiries, init_bitcoind, init_cli,
        update_balances, Transport, Wallet, FUND,
    },
    Channel, PtlcPoint, PtlcSecret, Splice, TX_FEE,
};

use anyhow::Result;
use bitcoin::{Amount, TxOut};
use futures::future;
use genawaiter::GeneratorState;
use spectral::prelude::*;

// NOTE: For some reason running these tests overflows the stack. In order to
// mitigate this run them with:
//
//     RUST_MIN_STACK=10000000 cargo test

#[tokio::test]
async fn e2e_channel_update() {
    // TODO: Work out how to declare cli and bitcoind inside create_channels().
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (mut a_channel, mut b_channel, mut a_transport, mut b_transport, _, _, time_lock, _) =
        create_channels(&bitcoind).await;

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).expect("failed to create amount");
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

    assert_channel_balances(&a_channel, &b_channel, a_balance, b_balance);
}

#[tokio::test]
async fn e2e_channel_collaborative_close() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        a_channel,
        b_channel,
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

    // No updates so this refunds the initial fund amount less tx fee (takes one
    // on-chain transaction).
    let a_close = a_channel.close(&mut a_transport, &a_wallet);
    let b_close = b_channel.close(&mut b_transport, &b_wallet);
    future::try_join(a_close, b_close).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    // We pay half a `TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Collaboratively closing the channel requires
    // publishing a single `CloseTransaction`, so each party pays
    // one half `TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(TX_FEE) / 2;

    // The balance after closing channel should equal balance after opening plus the
    // (refunded) fund amount minus tx fee.
    let a_want = a_balance_after_open + FUND - fee_deduction_per_output;
    let b_want = b_balance_after_open + FUND - fee_deduction_per_output;

    assert_eq!(a_balance_after_close, a_want);
    assert_eq!(b_balance_after_close, b_want);
}

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
async fn e2e_force_close_channel() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (a_channel, _, _, _, a_wallet, b_wallet, ..) = create_channels(&bitcoind).await;

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    a_channel.force_close(&a_wallet).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    // We pay half a `TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires publishing
    // both the `CommitTransaction` and the `SplitTransaction`, so each party pays
    // one `TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(TX_FEE);

    // The balance after closing channel should equal balance after opening plus the
    // (refunded) fund amount minus tx fee.
    let a_want = a_balance_after_open + FUND - fee_deduction_per_output;
    let b_want = b_balance_after_open + FUND - fee_deduction_per_output;

    assert_eq!(a_balance_after_close, a_want,);
    assert_eq!(b_balance_after_close, b_want,);
}

#[tokio::test]
async fn e2e_force_close_after_updates() {
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

    // Alice pays Bob 0.1 BTC
    let payment = Amount::from_btc(0.1).unwrap();
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

    a_channel.force_close(&a_wallet).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    let fee_deduction_per_output = Amount::from_sat(TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + FUND - payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus payment, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + FUND + payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus payment, minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_splice_in() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        a_channel,
        b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        _time_lock,
        tx_fee,
    ) = create_channels(&bitcoind).await;

    // This is the initial wallet amount (FUND + buffer) less the fund amount less
    // the transaction fee to open the channel.
    let a_wallet_balance_before_splice = a_wallet.balance().await.unwrap();
    let b_wallet_balance_before_splice = b_wallet.balance().await.unwrap();

    //  Alice splices in 0.5 BTC to the channel.
    //  Bob splices 0.1 BTC to the channel.

    let a_splice_in = Amount::from_btc(0.5).unwrap();
    let b_splice_in = Amount::from_btc(0.1).unwrap();

    let a_splice = a_channel.splice(&mut a_transport, &a_wallet, Splice::In(a_splice_in));
    let b_splice = b_channel.splice(&mut b_transport, &b_wallet, Splice::In(b_splice_in));
    let (a_channel, b_channel) = future::try_join(a_splice, b_splice).await.unwrap();

    // Assert the channel balances are as expected.
    let a_want = FUND + a_splice_in;
    let b_want = FUND + b_splice_in;
    assert_channel_balances(&a_channel, &b_channel, a_want, b_want);

    // Assert the wallet balances are as expected.
    let a_want = a_wallet_balance_before_splice - a_splice_in - tx_fee;
    let b_want = b_wallet_balance_before_splice - b_splice_in - tx_fee;
    let a_got = a_wallet.balance().await.unwrap();
    let b_got = b_wallet.balance().await.unwrap();
    assert_that!(a_got).is_equal_to(a_want);
    assert_that!(b_got).is_equal_to(b_want);
}

#[tokio::test]
async fn e2e_splice_out() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        a_channel,
        b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        _time_lock,
        _tx_fee,
    ) = create_channels(&bitcoind).await;

    // This is the initial wallet amount (FUND + buffer) less the fund amount less
    // the transaction fee to open the channel.
    let a_wallet_balance_before_splice = a_wallet.balance().await.unwrap();
    let b_wallet_balance_before_splice = b_wallet.balance().await.unwrap();

    //  Bob splices out (withdraws) 0.2 BTC
    let b_splice_address = b_wallet.0.new_address().await.unwrap();
    let b_splice_out = Amount::from_btc(0.2).unwrap();
    let b_splice = Splice::Out(TxOut {
        script_pubkey: b_splice_address.script_pubkey(),
        value: b_splice_out.as_sat(),
    });

    let a_splice = a_channel.splice(&mut a_transport, &a_wallet, Splice::None);
    let b_splice = b_channel.splice(&mut b_transport, &b_wallet, b_splice);
    let (a_channel, b_channel) = future::try_join(a_splice, b_splice).await.unwrap();

    let fee_deduction_per_output = Amount::from_sat(TX_FEE);

    // Assert the channel balances are as expected.
    let a_want = FUND;
    let b_want = FUND - b_splice_out - fee_deduction_per_output;
    assert_channel_balances(&a_channel, &b_channel, a_want, b_want);

    // Assert the wallet balances are as expected.
    let a_want = a_wallet_balance_before_splice;
    let b_want = b_wallet_balance_before_splice + b_splice_out;
    let a_got = a_wallet.balance().await.unwrap();
    let b_got = b_wallet.balance().await.unwrap();
    assert_that!(a_got).is_equal_to(a_want);
    assert_that!(b_got).is_equal_to(b_want);
}

// TODO: Fund alpha ledger (Bitcoin on-chain) and use the secret to redeem it as
// Bob
#[tokio::test]
async fn e2e_atomic_swap_happy() {
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

    assert_channel_balances(&a_channel, &b_channel, FUND, FUND);

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    let expiries = generate_expiries(&a_wallet).await.unwrap();

    let hold_secret = false;
    let swap_beta_ptlc_alice = a_channel.swap_beta_ptlc_alice(
        &mut a_transport,
        &a_wallet,
        ptlc_amount,
        secret,
        expiries.alpha_absolute,
        expiries.split_transaction_relative,
        expiries.ptlc_absolute,
        hold_secret,
    );

    let skip_final_update = false;
    let swap_beta_ptlc_bob_with_final_update = swap_beta_ptlc_bob(
        &mut b_channel,
        &mut b_transport,
        &b_wallet,
        ptlc_amount,
        point,
        expiries.alpha_absolute,
        expiries.split_transaction_relative,
        expiries.ptlc_absolute,
        skip_final_update,
    );

    future::try_join(swap_beta_ptlc_alice, swap_beta_ptlc_bob_with_final_update)
        .await
        .unwrap();

    a_channel.force_close(&a_wallet).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    let fee_deduction_per_output = Amount::from_sat(TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + FUND + ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + FUND - ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_atomic_swap_unresponsive_bob_after_secret_reveal() {
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

    assert_channel_balances(&a_channel, &b_channel, FUND, FUND);

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    // TODO: produce redeem and refund transactions + fund alpha

    let expiries = generate_expiries(&a_wallet).await.unwrap();

    let hold_secret = false;
    let swap_beta_ptlc_alice = a_channel.swap_beta_ptlc_alice(
        &mut a_transport,
        &a_wallet,
        ptlc_amount,
        secret,
        expiries.alpha_absolute,
        expiries.split_transaction_relative,
        expiries.ptlc_absolute,
        hold_secret,
    );

    let skip_final_update = true;
    let swap_beta_ptlc_bob_without_final_update = swap_beta_ptlc_bob(
        &mut b_channel,
        &mut b_transport,
        &b_wallet,
        ptlc_amount,
        point,
        expiries.alpha_absolute,
        expiries.split_transaction_relative,
        expiries.ptlc_absolute,
        skip_final_update,
    );

    future::try_join(
        swap_beta_ptlc_alice,
        swap_beta_ptlc_bob_without_final_update,
    )
    .await
    .unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    // A `SplitTransaction` containing a PTLC output has 2 balance outputs and 1
    // PTLC output, for a total of 3
    let n_outputs_split_transaction = 3;

    // The fees are distributed evenly between the outputs.
    let fee_deduction_per_split_output =
        Amount::from_sat(TX_FEE + TX_FEE) / n_outputs_split_transaction;

    // Alice will claim her balance output and a PTLC output.
    let split_transaction_fee_alice = fee_deduction_per_split_output * 2;

    // Bob will just claim his balance output.
    let split_transaction_fee_bob = fee_deduction_per_split_output;

    // Additionally, Alice pays an extra `TX_FEE` to be able to redeem the
    // PTLC output.
    let fee_deduction_for_ptlc_redeem = Amount::from_sat(TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + FUND + ptlc_amount
            - split_transaction_fee_alice - fee_deduction_for_ptlc_redeem,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + FUND - ptlc_amount - split_transaction_fee_bob,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[allow(clippy::too_many_arguments)]
async fn swap_beta_ptlc_bob(
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

            match swap_beta_ptlc_bob.async_resume().await {
                GeneratorState::Complete(Ok(())) => (),
                GeneratorState::Complete(Err(e)) => panic!("{}", e),
                GeneratorState::Yielded(_) => panic!("unexpected yield"),
            }
        }
        GeneratorState::Complete(Err(e)) => panic!("{}", e),
        GeneratorState::Complete(Ok(())) => panic!("did not yield secret"),
    }

    Ok(())
}
