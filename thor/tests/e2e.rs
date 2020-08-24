#![allow(non_snake_case)]

mod harness;

use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use harness::{make_transports, make_wallets};
use thor::{Balance, Channel};

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (_alice_channel, _bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();
}

#[tokio::test]
async fn e2e_channel_update() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount - payment;
    let bob_balance = fund_amount + payment;

    let alice_update = alice_channel.update(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Assert expected balance changes

    assert_eq!(alice_channel.balance().ours, alice_balance);
    assert_eq!(alice_channel.balance().theirs, bob_balance);

    assert_eq!(bob_channel.balance().ours, bob_balance);
    assert_eq!(bob_channel.balance().theirs, alice_balance);
}

#[tokio::test]
async fn e2e_punish_publication_of_revoked_commit_transaction() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    let after_open_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_open_balance_bob = bob_wallet.0.balance().await.unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount - payment;
    let bob_balance = fund_amount + payment;

    let alice_update = alice_channel.update(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Alice attempts to cheat by publishing a revoked commit transaction

    let signed_revoked_TX_c = alice_channel.latest_revoked_signed_TX_c().unwrap().unwrap();
    alice_wallet
        .0
        .send_raw_transaction(signed_revoked_TX_c.clone())
        .await
        .unwrap();

    // Bob sees the transaction and punishes Alice

    bob_channel
        .punish(&bob_wallet, signed_revoked_TX_c)
        .await
        .unwrap();

    let after_punish_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_punish_balance_bob = bob_wallet.0.balance().await.unwrap();

    assert_eq!(
        after_punish_balance_alice, after_open_balance_alice,
        "Alice should get no money back after being punished"
    );
    assert_eq!(
        after_punish_balance_bob,
        after_open_balance_bob + fund_amount * 2 - Amount::from_sat(thor::TX_FEE) * 2,
        "Bob should get all the money back after punishing Alice"
    );
}

#[tokio::test]
async fn e2e_channel_collaborative_close() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    let after_open_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_open_balance_bob = bob_wallet.0.balance().await.unwrap();

    let alice_close = alice_channel.close(&mut alice_transport, &alice_wallet);
    let bob_close = bob_channel.close(&mut bob_transport, &bob_wallet);

    futures::future::try_join(alice_close, bob_close)
        .await
        .unwrap();

    let after_close_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = bob_wallet.0.balance().await.unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Collaboratively closing the channel requires
    // publishing a single `CloseTransaction`, so each party pays
    // one half `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE) / 2;

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_force_close_channel() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, _bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    let after_open_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_open_balance_bob = bob_wallet.0.balance().await.unwrap();

    alice_channel.force_close(&alice_wallet).await.unwrap();

    let after_close_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = bob_wallet.0.balance().await.unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires publishing
    // both the `CommitTransaction` and the `SplitTransaction`, so each party pays
    // one `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
}
