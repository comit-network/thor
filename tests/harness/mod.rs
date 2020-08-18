use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount};
use bitcoin_harness::{bitcoind_rpc::PsbtBase64, Bitcoind};
use reqwest::Url;
use thor::{
    create::{self, BuildFundingPSBT, Party6, SignFundingPSBT},
    update,
};
use update::ChannelUpdate;

pub struct CreateActors {
    pub alice: create::Alice0,
    pub alice_wallet: Wallet,
    pub bob: create::Bob0,
    pub bob_wallet: Wallet,
}

pub async fn make_create_actors(
    bitcoind: &Bitcoind<'_>,
    alice_balance: Amount,
    bob_balance: Amount,
    time_lock: u32,
) -> CreateActors {
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

    CreateActors {
        alice,
        alice_wallet,
        bob,
        bob_wallet,
    }
}

pub struct Created {
    pub alice: Party6,
    pub bob: Party6,
}

pub async fn run_create_protocol<W>(
    alice_wallet: &W,
    alice0: create::Alice0,
    bob_wallet: &W,
    bob0: create::Bob0,
) -> Created
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

    Created {
        alice: alice6,
        bob: bob6,
    }
}

pub struct UpdateActors {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

pub fn make_update_actors(alice: create::Party6, bob: create::Party6) -> UpdateActors {
    let alice = update::Party0::new(alice);
    let bob = update::Party0::new(bob);

    UpdateActors { alice, bob }
}

pub struct Updated {
    pub alice: update::Party0,
    pub bob: update::Party0,
}

pub fn run_update_protocol(
    alice0: update::Party0,
    bob0: update::Party0,
    channel_update: ChannelUpdate,
    time_lock: u32,
) -> Updated {
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

    Updated {
        alice: alice5,
        bob: bob4,
    }
}

pub struct Wallet(pub bitcoin_harness::Wallet);

impl Wallet {
    pub async fn new(name: &str, url: Url) -> anyhow::Result<Self> {
        let wallet = bitcoin_harness::Wallet::new(name, url).await?;

        Ok(Self(wallet))
    }
}

#[async_trait::async_trait]
impl BuildFundingPSBT for Wallet {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> anyhow::Result<PartiallySignedTransaction> {
        let psbt = self.0.fund_psbt(output_address, output_amount).await?;
        let as_hex = base64::decode(psbt)?;

        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}

#[async_trait::async_trait]
impl SignFundingPSBT for Wallet {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> anyhow::Result<PartiallySignedTransaction> {
        let psbt = bitcoin::consensus::serialize(&psbt);
        let as_base64 = base64::encode(psbt);

        let psbt = self.0.wallet_process_psbt(PsbtBase64(as_base64)).await?;
        let PsbtBase64(signed_psbt) = PsbtBase64::from(psbt);

        let as_hex = base64::decode(signed_psbt)?;
        let psbt = bitcoin::consensus::deserialize(&as_hex)?;

        Ok(psbt)
    }
}
