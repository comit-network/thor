use bitcoin::Address;
use thor::{close, close::FinalState, Channel};

pub fn run(
    alice_channel: Channel,
    final_address_alice: Address,
    bob_channel: Channel,
    final_address_bob: Address,
) -> anyhow::Result<(FinalState, FinalState)> {
    let alice0: close::State0 = alice_channel.into();
    let bob0: close::State0 = bob_channel.into();

    let alice_message0 = alice0.compose(final_address_alice.clone());
    let bob_message0 = bob0.compose(final_address_bob.clone());

    let alice1 = alice0.interpret(final_address_alice, bob_message0);
    let bob1 = bob0.interpret(final_address_bob, alice_message0);

    let alice_message1 = alice1.compose()?;
    let bob_message1 = bob1.compose()?;

    let alice_final_state = alice1.interpret(bob_message1)?;
    let bob_final_state = bob1.interpret(alice_message1)?;

    Ok((alice_final_state, bob_final_state))
}
