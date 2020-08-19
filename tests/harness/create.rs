use crate::harness::Wallet;
use bitcoin::Amount;
use bitcoin_harness::Bitcoind;
use create::{BuildFundingPSBT, Party6, SignFundingPSBT};
use thor::create;

pub struct Init {
    pub alice: create::Alice0,
    pub alice_wallet: Wallet,
    pub bob: create::Bob0,
    pub bob_wallet: Wallet,
}

impl Init {
    pub async fn new(
        bitcoind: &Bitcoind<'_>,
        alice_balance: Amount,
        bob_balance: Amount,
        time_lock: u32,
    ) -> Self {
        bitcoind.init(5).await.unwrap();

        let alice_wallet = Wallet::new("alice", bitcoind.node_url.clone())
            .await
            .unwrap();
        let bob_wallet = Wallet::new("bob", bitcoind.node_url.clone()).await.unwrap();

        let buffer = Amount::from_btc(3.0).unwrap();

        {
            // TODO: Could pass in the wallet and generate the address inside?
            let address = alice_wallet.0.new_address().await.unwrap();
            bitcoind
                .mint(address, alice_balance + buffer)
                .await
                .unwrap();
        }

        {
            let address = bob_wallet.0.new_address().await.unwrap();
            bitcoind.mint(address, bob_balance + buffer).await.unwrap()
        };

        let alice = create::Alice0::new(alice_balance, time_lock);
        let bob = create::Bob0::new(bob_balance, time_lock);

        Self {
            alice,
            alice_wallet,
            bob,
            bob_wallet,
        }
    }
}

pub struct Final {
    pub alice: Party6,
    pub bob: Party6,
}

pub async fn run<W>(
    alice_wallet: &W,
    alice0: create::Alice0,
    bob_wallet: &W,
    bob0: create::Bob0,
) -> Final
where
    W: BuildFundingPSBT + SignFundingPSBT,
{
    let message0_alice = alice0.next_message();
    let message0_bob = bob0.next_message();

    let alice1 = alice0.receive(message0_bob, alice_wallet).await.unwrap();
    let bob1 = bob0.receive(message0_alice, bob_wallet).await.unwrap();

    let message1_alice = alice1.next_message();
    let message1_bob = bob1.next_message();

    let alice2 = alice1.receive(message1_bob).unwrap();
    let bob2 = bob1.receive(message1_alice).unwrap();

    let message2_alice = alice2.next_message();
    let message2_bob = bob2.next_message();

    let alice3 = alice2.receive(message2_bob).unwrap();
    let bob3 = bob2.receive(message2_alice).unwrap();

    let message3_alice = alice3.next_message();
    let message3_bob = bob3.next_message();

    let alice4 = alice3.receive(message3_bob).unwrap();
    let bob4 = bob3.receive(message3_alice).unwrap();

    let message4_alice = alice4.next_message();
    let message4_bob = bob4.next_message();

    let alice5 = alice4.receive(message4_bob).unwrap();
    let bob5 = bob4.receive(message4_alice).unwrap();

    let message5_alice = alice5.next_message(alice_wallet).await.unwrap();
    let message5_bob = bob5.next_message(bob_wallet).await.unwrap();

    let alice6 = alice5.receive(message5_bob, alice_wallet).await.unwrap();
    let bob6 = bob5.receive(message5_alice, bob_wallet).await.unwrap();

    Final {
        alice: alice6,
        bob: bob6,
    }
}
