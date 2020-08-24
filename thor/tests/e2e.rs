#![allow(non_snake_case)]

mod harness;

use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use harness::{make_transports, make_wallets};
use thor::{protocols::punish, Balance, Channel};

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let (alice_wallet, bob_wallet) = make_wallets(&bitcoind, fund_amount).await.unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (alice_channel, bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    assert_eq!(alice_channel.TX_f_body, bob_channel.TX_f_body);
    assert_eq!(
        alice_channel.current_state.TX_c,
        bob_channel.current_state.TX_c
    );
    assert_eq!(
        alice_channel.current_state.encsig_TX_c_self,
        bob_channel.current_state.encsig_TX_c_other
    );
    assert_eq!(
        alice_channel.current_state.encsig_TX_c_other,
        bob_channel.current_state.encsig_TX_c_self
    );
    assert_eq!(
        alice_channel.current_state.signed_TX_s,
        bob_channel.current_state.signed_TX_s
    );
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

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount - payment;
    let bob_balance = fund_amount + payment;

    let alice_update = alice_channel.update_alice(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_bob(
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

    assert_eq!(alice_channel.balance().unwrap().ours, alice_balance);
    assert_eq!(alice_channel.balance().unwrap().theirs, bob_balance);

    assert_eq!(bob_channel.balance().unwrap().ours, bob_balance);
    assert_eq!(bob_channel.balance().unwrap().theirs, alice_balance);

    // Assert new channel states match between parties

    assert_eq!(
        alice_channel.current_state.TX_c,
        bob_channel.current_state.TX_c
    );
    assert_eq!(
        alice_channel.current_state.encsig_TX_c_self,
        bob_channel.current_state.encsig_TX_c_other
    );
    assert_eq!(
        alice_channel.current_state.encsig_TX_c_other,
        bob_channel.current_state.encsig_TX_c_self
    );
    assert_eq!(
        alice_channel.current_state.signed_TX_s,
        bob_channel.current_state.signed_TX_s
    );
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

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount - payment;
    let bob_balance = fund_amount + payment;

    let alice_update = alice_channel.update_alice(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_bob(
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

    let bob = punish::State0::from(bob_channel);
    let TX_p = bob.punish(signed_revoked_TX_c).unwrap();

    bob_wallet
        .0
        .send_raw_transaction(TX_p.into())
        .await
        .unwrap();
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

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

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

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount - Amount::from_sat(thor::TX_FEE),
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount - Amount::from_sat(thor::TX_FEE),
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

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, _bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    let after_open_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_open_balance_bob = bob_wallet.0.balance().await.unwrap();

    alice_channel.force_close(&alice_wallet).await.unwrap();

    let after_close_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = bob_wallet.0.balance().await.unwrap();

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount - Amount::from_sat(thor::TX_FEE),
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount - Amount::from_sat(thor::TX_FEE),
        "Balance after closing channel should equal balance after opening minus transaction fees"
    );
}