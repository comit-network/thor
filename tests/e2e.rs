#![allow(non_snake_case)]

mod harness;

use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use harness::{
    make_create_actors, make_update_actors, run_create_protocol, run_update_protocol, CreateActors,
    Created, UpdateActors, Updated,
};
use thor::update::ChannelUpdate;

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();

    let time_lock = 1;
    let (alice_balance, bob_balance) = (Amount::ONE_BTC, Amount::ONE_BTC);

    let CreateActors {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    } = make_create_actors(&bitcoind, alice_balance, bob_balance, time_lock).await;

    let Created { alice, bob } = run_create_protocol(&alice_wallet, alice, &bob_wallet, bob).await;

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

    let CreateActors {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    } = make_create_actors(&bitcoind, alice_balance, bob_balance, time_lock).await;

    let Created { alice, bob } = run_create_protocol(&alice_wallet, alice, &bob_wallet, bob).await;

    assert_eq!(alice.signed_TX_f, bob.signed_TX_f);

    alice_wallet
        .0
        .send_raw_transaction(alice.signed_TX_f.clone())
        .await
        .unwrap();

    let UpdateActors { alice, bob } = make_update_actors(alice, bob);

    let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
    let time_lock = 1;

    let Updated { alice, bob } = run_update_protocol(alice, bob, channel_update, time_lock);

    assert_eq!(alice.balance().unwrap().ours, bob.balance().unwrap().theirs);
    assert_eq!(alice.balance().unwrap().theirs, bob.balance().unwrap().ours);
}
