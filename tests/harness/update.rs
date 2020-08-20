use thor::{update, update::ChannelUpdate, Channel};

pub struct Final {
    pub alice: Channel,
    pub bob: Channel,
}

pub fn run(
    alice_channel: Channel,
    bob_channel: Channel,
    channel_update: ChannelUpdate,
    time_lock: u32,
) -> Final {
    let alice0: update::State0 = alice_channel.into();
    let bob0: update::State0 = bob_channel.into();

    let (alice1, message0) = alice0.compose(channel_update, time_lock).unwrap();

    let (bob1, message1) = bob0.interpret(message0).unwrap();

    let alice2 = alice1.interpret(message1).unwrap();

    let message2_alice = alice2.compose();
    let message2_bob = bob1.compose();

    let alice3 = alice2.interpret(message2_bob).unwrap();
    let bob2 = bob1.interpret(message2_alice).unwrap();

    let message3_alice = alice3.compose();
    let message3_bob = bob2.compose();

    let alice4 = alice3.interpret(message3_bob).unwrap();
    let bob3 = bob2.interpret(message3_alice).unwrap();

    let message4_alice = alice4.compose();
    let message4_bob = bob3.compose();

    let alice5 = alice4.interpret(message4_bob).unwrap();
    let bob4 = bob3.interpret(message4_alice).unwrap();

    Final {
        alice: alice5,
        bob: bob4,
    }
}
