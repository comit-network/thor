#![allow(non_snake_case)]

mod harness;

use anyhow::Result;
use bitcoin::{Amount};
use bitcoin_harness::{self, Bitcoind};
use futures::future;
use genawaiter::GeneratorState;
use harness::{generate_balances, make_transports, make_wallets, Transport, Wallet};
use spectral::prelude::*;
use testcontainers::clients::Cli;
use thor::{Balance, Channel, PtlcPoint, PtlcSecret, Splice};

async fn create_channels(
    bitcoind: &Bitcoind<'_>,
) -> (
    Amount,
    Channel,
    Channel,
    Transport,
    Transport,
    Wallet,
    Wallet,
    u32,
    Amount,
) {
    let fund_amount = Amount::ONE_BTC;

    let (mut a_transport, mut b_transport) = make_transports();
    let (a_balance, b_balance) = generate_balances(fund_amount);
    let (a_wallet, b_wallet) = make_wallets(bitcoind, fund_amount)
        .await
        .expect("failed to make wallets");
    let time_lock = 1;

    let initial_balance = a_wallet.balance().await.unwrap();

    let a_create = Channel::create(&mut a_transport, &a_wallet, a_balance, time_lock);
    let b_create = Channel::create(&mut b_transport, &b_wallet, b_balance, time_lock);

    let (a_channel, b_channel) = future::try_join(a_create, b_create)
        .await
        .expect("failed to create channels");

    assert_channel_balances(&a_channel, &b_channel, fund_amount, fund_amount);

    let final_balance = a_wallet.balance().await.unwrap();
    let tx_fee = initial_balance - final_balance - fund_amount;

    (
        fund_amount,
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

fn assert_channel_balances(
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

async fn init_bitcoind(tc_client: &Cli) -> Bitcoind<'_> {
    let bitcoind = Bitcoind::new(tc_client, "0.19.1").expect("failed to create bitcoind");
    let _ = bitcoind.init(5).await;

    bitcoind
}

fn init_cli() -> Cli {
    Cli::default()
}

async fn update_balances(
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

#[tokio::test]
async fn e2e_channel_update() {
    // TODO: Work out how to declare cli and bitcoind inside create_channels().
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        fund_amount,
        mut a_channel,
        mut b_channel,
        mut a_transport,
        mut b_transport,
        _,
        _,
        time_lock,
        _,
    ) = create_channels(&bitcoind).await;

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).expect("failed to create amount");
    let a_balance = fund_amount - payment;
    let b_balance = fund_amount + payment;

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
        fund_amount,
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

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Collaboratively closing the channel requires
    // publishing a single `CloseTransaction`, so each party pays
    // one half `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE) / 2;

    // The balance after closing channel should equal balance after opening plus the
    // (refunded) fund amount minus tx fee.
    let a_want = a_balance_after_open + fund_amount - fee_deduction_per_output;
    let b_want = b_balance_after_open + fund_amount - fee_deduction_per_output;

    assert_eq!(a_balance_after_close, a_want);
    assert_eq!(b_balance_after_close, b_want);
}

#[tokio::test]
async fn e2e_punish_publication_of_revoked_commit_transaction() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        fund_amount,
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
    let a_balance = fund_amount - payment;
    let b_balance = fund_amount + payment;

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
        b_balance_after_open + fund_amount * 2 - Amount::from_sat(thor::TX_FEE) * 2,
        "Bob should get all the money back after punishing Alice"
    );
}

#[tokio::test]
async fn e2e_force_close_channel() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (fund_amount, a_channel, _, _, _, a_wallet, b_wallet, ..) =
        create_channels(&bitcoind).await;

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    a_channel.force_close(&a_wallet).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires publishing
    // both the `CommitTransaction` and the `SplitTransaction`, so each party pays
    // one `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    // The balance after closing channel should equal balance after opening plus the
    // (refunded) fund amount minus tx fee.
    let a_want = a_balance_after_open + fund_amount - fee_deduction_per_output;
    let b_want = b_balance_after_open + fund_amount - fee_deduction_per_output;

    assert_eq!(a_balance_after_close, a_want,);
    assert_eq!(b_balance_after_close, b_want,);
}

#[tokio::test]
async fn e2e_force_close_after_updates() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        fund_amount,
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
    let a_balance = fund_amount - payment;
    let b_balance = fund_amount + payment;
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

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires
    // publishing two transactions: a `CommitTransaction` and a `SplitTransaction`,
    // so each party pays a full `thor::TX_FEE`, which is deducted from their
    // output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + fund_amount - payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus payment, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + fund_amount + payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus payment, minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_splice_in() {
    // Arrange

    let tc_client = Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let (a_balance, b_balance) = generate_balances(fund_amount);

    let time_lock = 1;

    let (a_wallet, b_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut a_transport, mut b_transport) = make_transports();

    let before_create_a_balance = a_wallet.balance().await.unwrap();
    let before_create_b_balance = b_wallet.balance().await.unwrap();

    // Act: Create a new channel

    let a_create = Channel::create(&mut a_transport, &a_wallet, a_balance, time_lock);
    let b_create = Channel::create(&mut b_transport, &b_wallet, b_balance, time_lock);

    let (mut a_channel, mut b_channel) = future::try_join(a_create, b_create).await.unwrap();

    // Arrange: Save the fees for final asserts

    let mut bitcoind_fee_alice =
        before_create_a_balance - Amount::ONE_BTC - a_wallet.0.balance().await.unwrap();
    let mut bitcoind_fee_bob =
        before_create_b_balance - Amount::ONE_BTC - b_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 0.3 BTC

    let payment = Amount::from_btc(0.3).unwrap();
    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = a_channel.balance();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let a_update = a_channel.update_balance(
        &mut a_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let b_update = b_channel.update_balance(
        &mut b_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    future::try_join(a_update, b_update).await.unwrap();

    // Arrange: Save channel balances to check after the splice

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = a_channel.balance();

    // Act: Splice-in the channel:
    //  Alice adds 0.5 BTC to the channel, increasing her balance to 1.2 BTC.
    //  Bob adds 0.1 BTC to the channel, increasing his balance to 1.4 BTC

    let a_splice_in = Amount::from_btc(0.5).unwrap();
    let b_splice_in = Amount::from_btc(0.1).unwrap();

    let before_splice_alice_balance = a_wallet.0.balance().await.unwrap();
    let before_splice_bob_balance = b_wallet.0.balance().await.unwrap();

    let a_splice = a_channel.splice(&mut a_transport, &a_wallet, Splice::In(a_splice_in));
    let b_splice = b_channel.splice(&mut b_transport, &b_wallet, Splice::In(b_splice_in));

    let (mut a_channel, mut b_channel) = future::try_join(a_splice, b_splice).await.unwrap();

    // Assert: Channel balances are correct

    assert_eq!(actual_alice_balance + a_splice_in, a_channel.balance().ours);
    assert_eq!(actual_bob_balance + b_splice_in, b_channel.balance().ours);

    assert_eq!(a_channel.balance().ours, b_channel.balance().theirs);
    assert_eq!(a_channel.balance().theirs, b_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = a_channel.balance();

    bitcoind_fee_alice +=
        before_splice_alice_balance - a_splice_in - a_wallet.0.balance().await.unwrap();

    bitcoind_fee_bob +=
        before_splice_bob_balance - b_splice_in - b_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 1.0 BTC

    let payment = Amount::from_btc(1.0).unwrap();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let a_update = a_channel.update_balance(
        &mut a_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let b_update = b_channel.update_balance(
        &mut b_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    future::try_join(a_update, b_update).await.unwrap();

    // Act: Collaboratively close the channel

    let a_close = a_channel.close(&mut a_transport, &a_wallet);
    let b_close = b_channel.close(&mut b_transport, &b_wallet);

    futures::future::try_join(a_close, b_close).await.unwrap();

    let after_close_balance_alice = a_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = b_wallet.0.balance().await.unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Collaboratively closing the channel requires
    // publishing a single `CloseTransaction`, so each party pays
    // one half `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE / 2);

    // Alice paid Bob total 1.3 BTC
    let alice_paid_bob = Amount::from_btc(1.3).unwrap();

    assert_eq!(
        before_create_a_balance - alice_paid_bob - fee_deduction_per_output - bitcoind_fee_alice,
        after_close_balance_alice,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
    assert_eq!(
        before_create_b_balance + alice_paid_bob - fee_deduction_per_output - bitcoind_fee_bob,
        after_close_balance_bob,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
}

// TODO: Fund alpha ledger (Bitcoin on-chain) and use the secret to redeem it as
// Bob
#[tokio::test]
async fn e2e_atomic_swap_happy() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        fund_amount,
        mut a_channel,
        mut b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        _time_lock,
        _tx_fee,
    ) = create_channels(&bitcoind).await;

    assert_channel_balances(&a_channel, &b_channel, fund_amount, fund_amount);

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    let (alpha_absolute_expiry, tx_s_time_lock, ptlc_redeem_time_lock) = (1_598_875_222, 1, 1);

    let swap_beta_ptlc_alice = a_channel.swap_beta_ptlc_alice(
        &mut a_transport,
        &a_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
    );

    let skip_final_update = false;
    let swap_beta_ptlc_bob_with_final_update = swap_beta_ptlc_bob(
        &mut b_channel,
        &mut b_transport,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
        skip_final_update,
    );

    future::try_join(swap_beta_ptlc_alice, swap_beta_ptlc_bob_with_final_update)
        .await
        .unwrap();

    a_channel.force_close(&a_wallet).await.unwrap();

    let a_balance_after_close = a_wallet.balance().await.unwrap();
    let b_balance_after_close = b_wallet.balance().await.unwrap();

    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + fund_amount + ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + fund_amount - ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_atomic_swap_unresponsive_bob_after_secret_reveal() {
    let cli = init_cli();
    let bitcoind = init_bitcoind(&cli).await;
    let (
        fund_amount,
        mut a_channel,
        mut b_channel,
        mut a_transport,
        mut b_transport,
        a_wallet,
        b_wallet,
        _time_lock,
        _tx_fee,
    ) = create_channels(&bitcoind).await;

    assert_channel_balances(&a_channel, &b_channel, fund_amount, fund_amount);

    let a_balance_after_open = a_wallet.balance().await.unwrap();
    let b_balance_after_open = b_wallet.balance().await.unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    // TODO: produce redeem and refund transactions + fund alpha

    let (alpha_absolute_expiry, tx_s_time_lock, ptlc_redeem_time_lock) = (1_598_875_222, 1, 1);

    let swap_beta_ptlc_alice = a_channel.swap_beta_ptlc_alice(
        &mut a_transport,
        &a_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
    );

    let skip_final_update = true;
    let swap_beta_ptlc_bob_without_final_update = swap_beta_ptlc_bob(
        &mut b_channel,
        &mut b_transport,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
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
        Amount::from_sat(thor::TX_FEE + thor::TX_FEE) / n_outputs_split_transaction;

    // Alice will claim her balance output and a PTLC output.
    let split_transaction_fee_alice = fee_deduction_per_split_output * 2;

    // Bob will just claim his balance output.
    let split_transaction_fee_bob = fee_deduction_per_split_output;

    // Additionally, Alice pays an extra `thor::TX_FEE` to be able to redeem the
    // PTLC output.
    let fee_deduction_for_ptlc_redeem = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        a_balance_after_close,
        a_balance_after_open + fund_amount + ptlc_amount
            - split_transaction_fee_alice - fee_deduction_for_ptlc_redeem,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        b_balance_after_close,
        b_balance_after_open + fund_amount - ptlc_amount - split_transaction_fee_bob,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[allow(clippy::too_many_arguments)]
async fn swap_beta_ptlc_bob(
    channel: &mut Channel,
    b_transport: &mut Transport,
    ptlc_amount: Amount,
    point: PtlcPoint,
    alpha_absolute_expiry: u32,
    tx_s_time_lock: u32,
    ptlc_redeem_time_lock: u32,
    skip_update: bool,
) -> Result<()> {
    let mut swap_beta_ptlc_bob = channel.swap_beta_ptlc_bob(
        b_transport,
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
