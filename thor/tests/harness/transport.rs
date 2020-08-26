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
    async fn send_message(&mut self, message: Message) -> thor::Result<()> {
        let str = serde_json::to_string(&message)
            .map_err(|err| thor::Error::custom(format!("failed to encode message: {}", err)))?;
        self.sender
            .send(str)
            .await
            .map_err(|_| thor::Error::custom("failed to send message".to_string()))
    }
}

#[async_trait::async_trait]
impl ReceiveMessage for Transport {
    async fn receive_message(&mut self) -> thor::Result<Message> {
        let str = self
            .receiver
            .next()
            .await
            .ok_or_else(|| thor::Error::custom("failed to receive message".to_string()))?;
        let message = serde_json::from_str(&str)
            .map_err(|err| thor::Error::custom(format!("failed to decode message: {}", err)))?;
        Ok(message)
    }
}
