use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bitcoin::Amount;
use futures::{
    channel::{
        mpsc,
        mpsc::{Receiver, Sender},
    },
    SinkExt, StreamExt,
};

use thor::{Balance, Message, ReceiveMessage, SendMessage};

mod wallet;

pub use wallet::{make_wallets, Wallet};

pub fn generate_balances(fund_amount: Amount) -> (Balance, Balance) {
    _generate_balances(fund_amount, fund_amount)
}

fn _generate_balances(a_fund_amount: Amount, b_fund_amount: Amount) -> (Balance, Balance) {
    let a_balance = Balance {
        ours: a_fund_amount,
        theirs: b_fund_amount,
    };

    let b_balance = Balance {
        ours: b_fund_amount,
        theirs: a_fund_amount,
    };

    (a_balance, b_balance)
}

/// Create two mock `Transport`s which mimic a peer to peer connection between
/// two parties, allowing them to send and receive `thor::Message`s.
pub fn make_transports() -> (Transport, Transport) {
    let (a_sender, b_receiver) = mpsc::channel(5);
    let (b_sender, a_receiver) = mpsc::channel(5);

    let a_transport = Transport {
        sender: a_sender,
        receiver: a_receiver,
    };

    let b_transport = Transport {
        sender: b_sender,
        receiver: b_receiver,
    };

    (a_transport, b_transport)
}

pub struct Transport {
    // Using String instead of `Message` implicitly tests the `use-serde` feature.
    sender: Sender<String>,
    receiver: Receiver<String>,
}

#[async_trait]
impl SendMessage for Transport {
    async fn send_message(&mut self, message: Message) -> Result<()> {
        let str = serde_json::to_string(&message).context("failed to encode message")?;
        self.sender
            .send(str)
            .await
            .map_err(|_| anyhow!("failed to send message"))
    }
}

#[async_trait]
impl ReceiveMessage for Transport {
    async fn receive_message(&mut self) -> Result<Message> {
        let str = self
            .receiver
            .next()
            .await
            .ok_or_else(|| anyhow!("failed to receive message"))?;
        let message = serde_json::from_str(&str).context("failed to decode message")?;
        Ok(message)
    }
}
