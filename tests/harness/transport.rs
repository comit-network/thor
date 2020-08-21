use futures::{
    channel::mpsc::{Receiver, Sender},
    SinkExt, StreamExt,
};
use thor::{Message, ReceiveMessage, SendMessage};

pub struct Transport {
    sender: Sender<Message>,
    receiver: Receiver<Message>,
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
