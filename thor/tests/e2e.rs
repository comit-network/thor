#![allow(non_snake_case)]

mod harness;

use anyhow::Result;
use bitcoin::{Amount, TxOut};
use bitcoin_harness::{self, Bitcoind};
use genawaiter::GeneratorState;
use harness::{build_runtime, generate_balances, make_transports, make_wallets, Transport};
use thor::{Balance, Channel, PtlcPoint, PtlcSecret, Splice};

#[test]
fn e2e_channel_creation() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (_alice_channel, _bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();
}

#[test]
fn e2e_channel_update() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount_alice - payment;
    let bob_balance = fund_amount_bob + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    runtime
        .block_on(futures::future::try_join(alice_update, bob_update))
        .unwrap();

    // Assert expected balance changes

    assert_eq!(alice_channel.balance().ours, alice_balance);
    assert_eq!(alice_channel.balance().theirs, bob_balance);

    assert_eq!(bob_channel.balance().ours, bob_balance);
    assert_eq!(bob_channel.balance().theirs, alice_balance);
}

#[test]
fn e2e_punish_publication_of_revoked_commit_transaction() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount_alice - payment;
    let bob_balance = fund_amount_bob + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    runtime
        .block_on(futures::future::try_join(alice_update, bob_update))
        .unwrap();

    // Alice attempts to cheat by publishing a revoked commit transaction

    let signed_revoked_tx_c = alice_channel.latest_revoked_signed_tx_c().unwrap().unwrap();
    runtime
        .block_on(
            alice_wallet
                .0
                .send_raw_transaction(signed_revoked_tx_c.clone()),
        )
        .unwrap();

    // Bob sees the transaction and punishes Alice

    runtime
        .block_on(bob_channel.punish(&bob_wallet, signed_revoked_tx_c))
        .unwrap();

    let after_punish_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_punish_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    assert_eq!(
        after_punish_balance_alice, after_open_balance_alice,
        "Alice should get no money back after being punished"
    );
    assert_eq!(
        after_punish_balance_bob,
        after_open_balance_bob + fund_amount_bob * 2 - Amount::from_sat(thor::TX_FEE) * 2,
        "Bob should get all the money back after punishing Alice"
    );
}

#[test]
fn e2e_channel_collaborative_close() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (alice_channel, bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    let alice_close = alice_channel.close(&mut alice_transport, &alice_wallet);
    let bob_close = bob_channel.close(&mut bob_transport, &bob_wallet);

    runtime
        .block_on(futures::future::try_join(alice_close, bob_close))
        .unwrap();

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Collaboratively closing the channel requires
    // publishing a single `CloseTransaction`, so each party pays
    // one half `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE) / 2;

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount_alice - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount_bob - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
}

#[test]
fn e2e_force_close_channel() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (alice_channel, _bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    runtime
        .block_on(alice_channel.force_close(&alice_wallet))
        .unwrap();

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires publishing
    // both the `CommitTransaction` and the `SplitTransaction`, so each party pays
    // one `thor::TX_FEE`, which is deducted from their output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount_alice - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount_bob - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
}

#[test]
fn e2e_force_close_after_updates() {
    let mut runtime = build_runtime();

    // Arrange:

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    // Act:

    // Create a new channel

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_create_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_create_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // Alice pays Bob 0.1 BTC

    let payment = Amount::from_btc(0.1).unwrap();
    let alice_balance = fund_amount_alice - payment;
    let bob_balance = fund_amount_bob + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    runtime
        .block_on(futures::future::try_join(alice_update, bob_update))
        .unwrap();

    // Alice force closes the channel

    runtime
        .block_on(alice_channel.force_close(&alice_wallet))
        .unwrap();

    // Assert:

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires
    // publishing two transactions: a `CommitTransaction` and a `SplitTransaction`,
    // so each party pays a full `thor::TX_FEE`, which is deducted from their
    // output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_create_balance_alice + fund_amount_alice - payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus payment, minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_create_balance_bob + fund_amount_bob + payment - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus payment, minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_splice_in() {
    // Arrange

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob)
        .await
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let before_create_balance_alice = alice_wallet.0.balance().await.unwrap();
    let before_create_balance_bob = bob_wallet.0.balance().await.unwrap();

    // Act: Create a new channel

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Arrange: Save the fees for final asserts

    let mut bitcoind_fee_alice =
        before_create_balance_alice - Amount::ONE_BTC - alice_wallet.0.balance().await.unwrap();
    let mut bitcoind_fee_bob =
        before_create_balance_bob - Amount::ONE_BTC - bob_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 0.3 BTC

    let payment = Amount::from_btc(0.3).unwrap();
    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Arrange: Save channel balances to check after the splice

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    // Act: Splice-in the channel:
    //  Alice adds 0.5 BTC to the channel, increasing her balance to 1.2 BTC.
    //  Bob adds 0.1 BTC to the channel, increasing his balance to 1.4 BTC

    let alice_splice_in = Amount::from_btc(0.5).unwrap();
    let bob_splice_in = Amount::from_btc(0.1).unwrap();

    let before_splice_alice_balance = alice_wallet.0.balance().await.unwrap();
    let before_splice_bob_balance = bob_wallet.0.balance().await.unwrap();

    let alice_splice = alice_channel.splice(
        &mut alice_transport,
        &alice_wallet,
        Splice::In(alice_splice_in),
    );
    let bob_splice = bob_channel.splice(&mut bob_transport, &bob_wallet, Splice::In(bob_splice_in));

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_splice, bob_splice)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(
        actual_alice_balance + alice_splice_in,
        alice_channel.balance().ours
    );
    assert_eq!(
        actual_bob_balance + bob_splice_in,
        bob_channel.balance().ours
    );

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    bitcoind_fee_alice +=
        before_splice_alice_balance - alice_splice_in - alice_wallet.0.balance().await.unwrap();

    bitcoind_fee_bob +=
        before_splice_bob_balance - bob_splice_in - bob_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 1.0 BTC

    let payment = Amount::from_btc(1.0).unwrap();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Act: Collaboratively close the channel

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
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE / 2);

    // Alice paid Bob total 1.3 BTC
    let alice_paid_bob = Amount::from_btc(1.3).unwrap();

    assert_eq!(
        before_create_balance_alice
            - alice_paid_bob
            - fee_deduction_per_output
            - bitcoind_fee_alice,
        after_close_balance_alice,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
    assert_eq!(
        before_create_balance_bob + alice_paid_bob - fee_deduction_per_output - bitcoind_fee_bob,
        after_close_balance_bob,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_splice_out() {
    // Arrange

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount, fund_amount)
        .await
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let before_create_balance_alice = alice_wallet.0.balance().await.unwrap();
    let before_create_balance_bob = bob_wallet.0.balance().await.unwrap();

    // Act: Create a new channel

    let balance = Balance {
        ours: fund_amount,
        theirs: fund_amount,
    };

    let alice_create = Channel::create(&mut alice_transport, &alice_wallet, balance, time_lock);
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Assert: Channel balances are synced and correct:

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);
    assert_eq!(alice_channel.balance().ours, Amount::ONE_BTC);
    assert_eq!(bob_channel.balance().ours, Amount::ONE_BTC);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    let bitcoind_fee_alice =
        before_create_balance_alice - Amount::ONE_BTC - alice_wallet.0.balance().await.unwrap();
    let mut bitcoind_fee_bob =
        before_create_balance_bob - Amount::ONE_BTC - bob_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 0.3 BTC

    let payment = Amount::from_btc(0.3).unwrap();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(expected_alice_balance, alice_channel.balance().ours);
    assert_eq!(expected_bob_balance, bob_channel.balance().ours);

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    // Act: Splice-out the channel:
    //  Bob withdraws 1.2BTC, decreasing his channel balance to 0.1 BTC
    let bob_splice_address = bob_wallet.0.new_address().await.unwrap();
    let bob_splice_out_amount = Amount::from_btc(1.2).unwrap();
    let bob_splice = Splice::Out(TxOut {
        script_pubkey: bob_splice_address.script_pubkey(),
        value: bob_splice_out_amount.as_sat(),
    });

    let before_splice_bob_balance = bob_wallet.0.balance().await.unwrap();

    let alice_splice = alice_channel.splice(&mut alice_transport, &alice_wallet, Splice::None);
    let bob_splice = bob_channel.splice(&mut bob_transport, &bob_wallet, bob_splice);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_splice, bob_splice)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    let splice_out_fee = Amount::from_sat(thor::TX_FEE);

    assert_eq!(actual_alice_balance, alice_channel.balance().ours);
    assert_eq!(
        actual_bob_balance - bob_splice_out_amount - splice_out_fee,
        bob_channel.balance().ours
    );

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    bitcoind_fee_bob +=
        before_splice_bob_balance + bob_splice_out_amount - bob_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 0.5 BTC

    let payment = Amount::from_btc(0.5).unwrap();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(expected_alice_balance, alice_channel.balance().ours);
    assert_eq!(expected_bob_balance, bob_channel.balance().ours);

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_channel_balance_alice,
        theirs: actual_channel_balance_bob,
    } = alice_channel.balance();

    assert_eq!(actual_channel_balance_alice, Amount::from_btc(0.2).unwrap());
    assert_eq!(
        actual_channel_balance_bob,
        Amount::from_btc(0.5999).unwrap()
    );

    // Act: Collaboratively close the channel

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
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE / 2);

    // Alice paid Bob total 1.3 BTC
    let alice_paid_bob = Amount::from_btc(0.8).unwrap();

    assert_eq!(
        before_create_balance_alice
            - alice_paid_bob
            - fee_deduction_per_output
            - bitcoind_fee_alice,
        after_close_balance_alice,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
    assert_eq!(
        before_create_balance_bob + alice_paid_bob
            - fee_deduction_per_output
            - bitcoind_fee_bob
            - splice_out_fee,
        after_close_balance_bob,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
}

#[tokio::test]
async fn e2e_channel_splice_in_and_force_close() {
    // Arrange

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob)
        .await
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let before_create_balance_alice = alice_wallet.0.balance().await.unwrap();
    let before_create_balance_bob = bob_wallet.0.balance().await.unwrap();

    // Act: Create a new channel

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Assert: Channel balances are synced:

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    let mut bitcoind_fee_alice =
        before_create_balance_alice - Amount::ONE_BTC - alice_wallet.0.balance().await.unwrap();
    let bitcoind_fee_bob =
        before_create_balance_bob - Amount::ONE_BTC - bob_wallet.0.balance().await.unwrap();

    // Act: Alice pays Bob 0.9 BTC

    let payment = Amount::from_btc(0.9).unwrap();
    let expected_alice_balance = actual_alice_balance - payment;
    let expected_bob_balance = actual_bob_balance + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(expected_alice_balance, alice_channel.balance().ours);
    assert_eq!(expected_bob_balance, bob_channel.balance().ours);

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    // Act: Splice-in the channel, Alice adds 0.5 BTC to the channel

    let alice_splice_in = Amount::from_btc(0.5).unwrap();

    let before_splice_alice_balance = alice_wallet.0.balance().await.unwrap();

    let alice_splice = alice_channel.splice(
        &mut alice_transport,
        &alice_wallet,
        Splice::In(alice_splice_in),
    );
    let bob_splice = bob_channel.splice(&mut bob_transport, &bob_wallet, Splice::None);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_splice, bob_splice)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(
        actual_alice_balance + alice_splice_in,
        alice_channel.balance().ours
    );
    assert_eq!(actual_bob_balance, bob_channel.balance().ours);

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    let Balance {
        ours: actual_alice_balance,
        theirs: actual_bob_balance,
    } = alice_channel.balance();

    bitcoind_fee_alice +=
        before_splice_alice_balance - alice_splice_in - alice_wallet.0.balance().await.unwrap();

    // Act: Bob pays Alice 0.3 BTC

    let payment = Amount::from_btc(0.3).unwrap();
    let expected_alice_balance = actual_alice_balance + payment;
    let expected_bob_balance = actual_bob_balance - payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: expected_alice_balance,
            theirs: expected_bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: expected_bob_balance,
            theirs: expected_alice_balance,
        },
        time_lock,
    );

    futures::future::try_join(alice_update, bob_update)
        .await
        .unwrap();

    // Assert: Channel balances are correct

    assert_eq!(expected_alice_balance, alice_channel.balance().ours);
    assert_eq!(expected_bob_balance, bob_channel.balance().ours);

    assert_eq!(alice_channel.balance().ours, bob_channel.balance().theirs);
    assert_eq!(alice_channel.balance().theirs, bob_channel.balance().ours);

    // Act: Alice forces close the channel

    alice_channel.force_close(&alice_wallet).await.unwrap();

    let after_close_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = bob_wallet.0.balance().await.unwrap();
    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires
    // publishing two transactions: a `CommitTransaction` and a `SplitTransaction`,
    // so each party pays a full `thor::TX_FEE`, which is deducted from their
    // output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    let alice_paid_bob = Amount::from_btc(0.9).unwrap();
    let bob_paid_alice = Amount::from_btc(0.3).unwrap();

    assert_eq!(
        before_create_balance_alice - alice_paid_bob + bob_paid_alice
            - fee_deduction_per_output
            - bitcoind_fee_alice,
        after_close_balance_alice,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
    assert_eq!(
        before_create_balance_bob - bob_paid_alice + alice_paid_bob
            - fee_deduction_per_output
            - bitcoind_fee_bob,
        after_close_balance_bob,
        "Balance after closing channel should match in channel payment minus transaction fees"
    );
}

// TODO: Fund alpha ledger (Bitcoin on-chain) and use the secret to redeem it as
// Bob
#[test]
fn e2e_atomic_swap_happy() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    let (alpha_absolute_expiry, tx_s_time_lock, ptlc_redeem_time_lock) = (1_598_875_222, 1, 1);

    let swap_beta_ptlc_alice = alice_channel.swap_beta_ptlc_alice(
        &mut alice_transport,
        &alice_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
    );

    let skip_final_update = false;
    let swap_beta_ptlc_bob_with_final_update = swap_beta_ptlc_bob(
        &mut bob_channel,
        &mut bob_transport,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
        skip_final_update,
    );

    runtime
        .block_on(futures::future::try_join(
            swap_beta_ptlc_alice,
            swap_beta_ptlc_bob_with_final_update,
        ))
        .unwrap();

    runtime
        .block_on(alice_channel.force_close(&alice_wallet))
        .unwrap();

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // We pay half a `thor::TX_FEE` per output in fees for each transaction after
    // the `FundingTransaction`. Force closing the channel requires
    // publishing two transactions: a `CommitTransaction` and a `SplitTransaction`,
    // so each party pays a full `thor::TX_FEE`, which is deducted from their
    // output.
    let fee_deduction_per_output = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount_alice + ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount_bob - ptlc_amount - fee_deduction_per_output,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[test]
fn e2e_atomic_swap_unresponsive_bob_after_secret_reveal() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    // TODO: produce redeem and refund transactions + fund alpha

    let (alpha_absolute_expiry, tx_s_time_lock, ptlc_redeem_time_lock) = (1_598_875_222, 1, 1);

    let swap_beta_ptlc_alice = alice_channel.swap_beta_ptlc_alice(
        &mut alice_transport,
        &alice_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
    );

    let skip_final_update = true;
    let swap_beta_ptlc_bob_without_final_update = swap_beta_ptlc_bob(
        &mut bob_channel,
        &mut bob_transport,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        tx_s_time_lock,
        ptlc_redeem_time_lock,
        skip_final_update,
    );

    runtime
        .block_on(futures::future::try_join(
            swap_beta_ptlc_alice,
            swap_beta_ptlc_bob_without_final_update,
        ))
        .unwrap();

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // A `SplitTransaction` containing a PTLC output has 2 balance outputs and 1
    // PTLC output, for a total of 3
    let n_outputs_split_transaction = 3;

    // The fees are distributed evenly between the outputs.
    let fee_deduction_per_split_output =
        Amount::from_sat(thor::TX_FEE + thor::TX_FEE) / n_outputs_split_transaction;

    // Alice will claim her balance output and a PTLC output
    let split_transaction_fee_alice = fee_deduction_per_split_output * 2;

    // Bob will just claim his balance output
    let split_transaction_fee_bob = fee_deduction_per_split_output;

    // Additionally, Alice pays an extra `thor::TX_FEE` to be able to redeem the
    // PTLC output.
    let fee_deduction_for_ptlc_redeem = Amount::from_sat(thor::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount_alice + ptlc_amount
            - split_transaction_fee_alice - fee_deduction_for_ptlc_redeem,
        "Balance after closing channel should equal balance after opening plus PTLC amount, minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount_bob - ptlc_amount - split_transaction_fee_bob,
        "Balance after closing channel should equal balance after opening minus PTLC amount, minus transaction fees"
    );
}

#[allow(clippy::too_many_arguments)]
async fn swap_beta_ptlc_bob(
    channel: &mut Channel,
    bob_transport: &mut Transport,
    ptlc_amount: Amount,
    point: PtlcPoint,
    alpha_absolute_expiry: u32,
    tx_s_time_lock: u32,
    ptlc_redeem_time_lock: u32,
    skip_update: bool,
) -> Result<()> {
    let mut swap_beta_ptlc_bob = channel.swap_beta_ptlc_bob(
        bob_transport,
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
