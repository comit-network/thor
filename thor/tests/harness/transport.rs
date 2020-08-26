use anyhow::Context;
use futures::{
    channel::mpsc::{Receiver, Sender},
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
}

#[async_trait::async_trait]
impl SendMessage for Transport {
    type Error = anyhow::Error;

    async fn send_message(&mut self, message: Message) -> anyhow::Result<()> {
        let str = serde_json::to_string(&message).context("failed to encode message")?;
        self.sender
            .send(str)
            .await
            .map_err(|_| anyhow::anyhow!("failed to send message"))
    }
}

#[async_trait::async_trait]
impl ReceiveMessage for Transport {
    type Error = anyhow::Error;

    async fn receive_message(&mut self) -> anyhow::Result<Message> {
        let str = self
            .receiver
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("failed to receive message"))?;
        let message = serde_json::from_str(&str).context("failed to decode message")?;
        Ok(message)
    }
}
