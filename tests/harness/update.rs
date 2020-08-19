use thor::{update, update::ChannelUpdate};

pub struct Init {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

impl Init {
    pub fn new(alice: thor::create::Party6, bob: thor::create::Party6) -> Self {
        let alice = update::Party0::new(alice);
        let bob = update::Party0::new(bob);

        Self { alice, bob }
    }
}

pub struct Final {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

pub fn run(
    alice0: update::Party0,
    bob0: update::Party0,
    channel_update: ChannelUpdate,
    time_lock: u32,
) -> Final {
    let (alice1, message0) = alice0
        .propose_channel_update(channel_update, time_lock)
        .unwrap();

    let (bob1, message1) = bob0.receive_channel_update(message0).unwrap();

    let alice2 = alice1.receive(message1).unwrap();

    let message2_alice = alice2.next_message();
    let message2_bob = bob1.next_message();

    let alice3 = alice2.receive(message2_bob).unwrap();
    let bob2 = bob1.receive(message2_alice).unwrap();

    let message3_alice = alice3.next_message();
    let message3_bob = bob2.next_message();

    let alice4 = alice3.receive(message3_bob).unwrap();
    let bob3 = bob2.receive(message3_alice).unwrap();

    let message4_alice = alice4.next_message();
    let message4_bob = bob3.next_message();

    let alice5 = alice4.receive(message4_bob).unwrap();
    let bob4 = bob3.receive(message4_alice).unwrap();

    Final {
        alice: alice5,
        bob: bob4,
    }
}
