use bitcoin::{Address, Transaction};
use thor::{close, Channel};

pub fn run(
    alice_channel: Channel,
    final_address_alice: Address,
    bob_channel: Channel,
    final_address_bob: Address,
) -> anyhow::Result<(Transaction, Transaction)> {
    let alice0 = close::State0::new(alice_channel, final_address_alice);
    let bob0 = close::State0::new(bob_channel, final_address_bob);

    let alice_message0 = alice0.compose();
    let bob_message0 = bob0.compose();

    let alice1 = alice0.interpret(bob_message0);
    let bob1 = bob0.interpret(alice_message0);

    let alice_message1 = alice1.compose()?;
    let bob_message1 = bob1.compose()?;

    let alice_close_transaction = alice1.interpret(bob_message1)?;
    let bob_close_transaction = bob1.interpret(alice_message1)?;

    Ok((alice_close_transaction, bob_close_transaction))
}
