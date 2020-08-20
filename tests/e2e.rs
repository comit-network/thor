#![allow(non_snake_case)]

mod harness;

use crate::harness::close;
use bitcoin::Amount;
use bitcoin_harness::{self, Bitcoind};
use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use harness::{update, Wallet};
use thor::{punish, update::ChannelUpdate, Channel, Message, ReceiveMessage, SendMessage};

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

    let (alice, bob) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    assert_eq!(alice.TX_f_body, bob.TX_f_body);
    assert_eq!(alice.current_state.TX_c, bob.current_state.TX_c);
    assert_eq!(
        alice.current_state.encsig_TX_c_self,
        bob.current_state.encsig_TX_c_other
    );
    assert_eq!(
        alice.current_state.encsig_TX_c_other,
        bob.current_state.encsig_TX_c_self
    );
    assert_eq!(
        alice.current_state.signed_TX_s,
        bob.current_state.signed_TX_s
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

    let (alice_channel, bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
    let time_lock = 1;

    let update::Final { alice, bob } =
        update::run(alice_channel, bob_channel, channel_update, time_lock);

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

    let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
    let time_lock = 1;

    let update::Final { alice, bob } =
        update::run(alice_channel, bob_channel, channel_update, time_lock);

    // Alice attempts to cheat by publishing a revoked commit transaction

    let signed_revoked_TX_c = alice.latest_revoked_signed_TX_c().unwrap().unwrap();
    alice_wallet
        .0
        .send_raw_transaction(signed_revoked_TX_c.clone())
        .await
        .unwrap();

    // Bob sees the transaction and punishes Alice

    let bob = punish::State0::from(bob);
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

    let (alice_channel, bob_channel) = futures::future::try_join(alice_create, bob_create)
        .await
        .unwrap();

    // Start closing channel
    let alice_final_address = alice_wallet.0.new_address().await.unwrap();
    let bob_final_address = bob_wallet.0.new_address().await.unwrap();

    let (alice_closing_transaction, bob_closing_transaction) = close::run(
        alice_channel,
        alice_final_address,
        bob_channel,
        bob_final_address,
    )
    .unwrap();

    assert_eq!(alice_closing_transaction, bob_closing_transaction);

    // ugly wait for 1 block
    tokio::time::delay_for(std::time::Duration::from_millis(1100)).await;
    let before_closure_amount_alice = alice_wallet.0.balance().await.unwrap();
    let before_closure_amount_bob = bob_wallet.0.balance().await.unwrap();

    alice_wallet
        .0
        .send_raw_transaction(alice_closing_transaction)
        .await
        .unwrap();

    // ugly wait for 1 block
    tokio::time::delay_for(std::time::Duration::from_millis(1100)).await;
    let after_closure_amount_alice = alice_wallet.0.balance().await.unwrap();
    let after_closure_amount_bob = bob_wallet.0.balance().await.unwrap();

    // difference should be last channel balance - fees
    let amount_difference_alice = after_closure_amount_alice - before_closure_amount_alice;
    assert_eq!(
        amount_difference_alice,
        fund_amount - Amount::from_sat(thor::TX_FEE),
        "Balance difference before and after channel closure should be initial channel funding minus transaction fees"
    );
    let amount_difference_bob = after_closure_amount_bob - before_closure_amount_bob;
    assert_eq!(
        amount_difference_bob,
        fund_amount - Amount::from_sat(thor::TX_FEE),
        "Balance difference before and after channel closure should be initial channel funding minus transaction fees"
    );
}
