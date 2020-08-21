#![allow(non_snake_case)]

mod harness;

use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use harness::Wallet;
use thor::{punish, Balance, Channel, Message, ReceiveMessage, SendMessage};

struct Transport {
    sender: Sender<Message>,
    receiver: Receiver<Message>,
}

#[async_trait::async_trait]
impl SendMessage for Transport {
    async fn send_message(&mut self, message: Message) -> anyhow::Result<()> {
        self.sender
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("failed to send message"))
    }
}

#[async_trait::async_trait]
impl ReceiveMessage for Transport {
    async fn receive_message(&mut self) -> anyhow::Result<Message> {
        self.receiver
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("failed to send message"))
    }
}

#[tokio::test]
async fn e2e_channel_creation() {
    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();

    bitcoind.init(5).await.unwrap();

    let fund_amount = Amount::ONE_BTC;
    let time_lock = 1;

    let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
        .await
        .unwrap();
    let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

    let buffer = Amount::from_btc(1.0).unwrap();

    {
        let address = alice_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap();
    }

    {
        let address = bob_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap()
    };

    let (mut alice_transport, mut bob_transport) = {
        let (alice_sender, bob_receiver) = futures::channel::mpsc::channel(5);
        let (bob_sender, alice_receiver) = futures::channel::mpsc::channel(5);

        let alice_transport = Transport {
            sender: alice_sender,
            receiver: alice_receiver,
        };

        let bob_transport = Transport {
            sender: bob_sender,
            receiver: bob_receiver,
        };

        (alice_transport, bob_transport)
    };

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

    let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
        .await
        .unwrap();
    let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

    let buffer = Amount::from_btc(1.0).unwrap();

    {
        let address = alice_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap();
    }

    {
        let address = bob_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap()
    };

    let (mut alice_transport, mut bob_transport) = {
        let (alice_sender, bob_receiver) = futures::channel::mpsc::channel(5);
        let (bob_sender, alice_receiver) = futures::channel::mpsc::channel(5);

        let alice_transport = Transport {
            sender: alice_sender,
            receiver: alice_receiver,
        };

        let bob_transport = Transport {
            sender: bob_sender,
            receiver: bob_receiver,
        };

        (alice_transport, bob_transport)
    };

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

    let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
        .await
        .unwrap();
    let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

    let buffer = Amount::from_btc(1.0).unwrap();

    {
        let address = alice_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap();
    }

    {
        let address = bob_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap()
    };

    let (mut alice_transport, mut bob_transport) = {
        let (alice_sender, bob_receiver) = futures::channel::mpsc::channel(5);
        let (bob_sender, alice_receiver) = futures::channel::mpsc::channel(5);

        let alice_transport = Transport {
            sender: alice_sender,
            receiver: alice_receiver,
        };

        let bob_transport = Transport {
            sender: bob_sender,
            receiver: bob_receiver,
        };

        (alice_transport, bob_transport)
    };

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

    let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
        .await
        .unwrap();
    let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

    let buffer = Amount::from_btc(1.0).unwrap();

    {
        let address = alice_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap();
    }

    {
        let address = bob_wallet.0.new_address().await.unwrap();
        bitcoind.mint(address, fund_amount + buffer).await.unwrap()
    };

    let (mut alice_transport, mut bob_transport) = {
        let (alice_sender, bob_receiver) = futures::channel::mpsc::channel(5);
        let (bob_sender, alice_receiver) = futures::channel::mpsc::channel(5);

        let alice_transport = Transport {
            sender: alice_sender,
            receiver: alice_receiver,
        };

        let bob_transport = Transport {
            sender: bob_sender,
            receiver: bob_receiver,
        };

        (alice_transport, bob_transport)
    };

    let alice_create =
        Channel::create_alice(&mut alice_transport, &alice_wallet, fund_amount, time_lock);
    let bob_create = Channel::create_bob(&mut bob_transport, &bob_wallet, fund_amount, time_lock);

    let (mut alice_channel, mut bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // give time for fund transaction to be mined
    tokio::time::delay_for(std::time::Duration::from_millis(1100)).await;

    let after_open_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_open_balance_bob = bob_wallet.0.balance().await.unwrap();

    let alice_close = alice_channel.close(&mut alice_transport, &alice_wallet);
    let bob_close = bob_channel.close(&mut bob_transport, &bob_wallet);

    futures::future::try_join(alice_close, bob_close)
        .await
        .unwrap();

    // give time for close transaction to be mined
    tokio::time::delay_for(std::time::Duration::from_millis(2000)).await;

    let after_close_balance_alice = alice_wallet.0.balance().await.unwrap();
    let after_close_balance_bob = bob_wallet.0.balance().await.unwrap();

    // difference should be last channel balance - fees
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
