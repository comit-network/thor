#![allow(non_snake_case)]

mod harness;

use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use harness::{create, update};
use thor::{punish, update::ChannelUpdate};

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();

    let time_lock = 1;
    let (alice_balance, bob_balance) = (Amount::ONE_BTC, Amount::ONE_BTC);

    let create::Init {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    } = create::Init::new(&bitcoind, alice_balance, bob_balance, time_lock).await;

    let create::Final { alice, bob } = create::run(&alice_wallet, alice, &bob_wallet, bob).await;

    assert_eq!(alice.signed_TX_f, bob.signed_TX_f);

    alice_wallet
        .0
        .send_raw_transaction(alice.signed_TX_f.clone())
        .await
        .unwrap();
}

#[tokio::test]
async fn e2e_channel_update() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();

    let time_lock = 1;
    let (alice_balance, bob_balance) = (Amount::ONE_BTC, Amount::ONE_BTC);

    let create::Init {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    } = create::Init::new(&bitcoind, alice_balance, bob_balance, time_lock).await;

    let create::Final { alice, bob } = create::run(&alice_wallet, alice, &bob_wallet, bob).await;

    alice_wallet
        .0
        .send_raw_transaction(alice.signed_TX_f.clone())
        .await
        .unwrap();

    let update::Init { alice, bob } = update::Init::new(alice, bob);

    let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
    let time_lock = 1;

    let update::Final { alice, bob } = update::run(alice, bob, channel_update, time_lock);

    assert_eq!(
        alice.balance().unwrap().ours,
        Amount::from_btc(0.5).unwrap()
    );
    assert_eq!(
        alice.balance().unwrap().theirs,
        Amount::from_btc(1.5).unwrap()
    );

    assert_eq!(bob.balance().unwrap().ours, Amount::from_btc(1.5).unwrap());
    assert_eq!(
        bob.balance().unwrap().theirs,
        Amount::from_btc(0.5).unwrap()
    );
}

#[tokio::test]
async fn e2e_punish_publication_of_revoked_commit_transaction() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();

    let time_lock = 1;
    let (alice_balance, bob_balance) = (Amount::ONE_BTC, Amount::ONE_BTC);

    let create::Init {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    } = create::Init::new(&bitcoind, alice_balance, bob_balance, time_lock).await;

    let create::Final { alice, bob } = create::run(&alice_wallet, alice, &bob_wallet, bob).await;

    alice_wallet
        .0
        .send_raw_transaction(alice.signed_TX_f.clone())
        .await
        .unwrap();

    let update::Init { alice, bob } = update::Init::new(alice, bob);

    let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
    let time_lock = 1;

    let update::Final { alice, bob } = update::run(alice, bob, channel_update, time_lock);

    // Alice attempts to cheat by publishing a revoked commit transaction

    let signed_revoked_TX_c = alice.latest_revoked_signed_TX_c().unwrap().unwrap();
    alice_wallet
        .0
        .send_raw_transaction(signed_revoked_TX_c.clone())
        .await
        .unwrap();

    // Bob sees the transaction and punishes Alice

    let bob = punish::Party0::from(bob);
    let TX_p = bob.punish(signed_revoked_TX_c).unwrap();

    bob_wallet
        .0
        .send_raw_transaction(TX_p.into())
        .await
        .unwrap();
}