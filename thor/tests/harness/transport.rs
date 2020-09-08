use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures::{
    channel::{
        mpsc,
        mpsc::{Receiver, Sender},
    },
    SinkExt, StreamExt,
};
use thor::{Message, ReceiveMessage, SendMessage};

pub struct Transport {
    // While it would be more efficient to use `Message` this allows us to test the `use-serde`
    // feature
    sender: Sender<String>,
    receiver: Receiver<String>,
}

/// Create two `Transport`s which mimic a peer to peer connection between two
/// parties, allowing them to send and receive `thor::Message`s to and from each
/// other.
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
