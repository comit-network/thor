use crate::{transaction::CloseTransaction, Channel};
use bitcoin::{Address, Transaction};
use ecdsa_fun::Signature;

pub struct State0(Channel);
pub struct State1 {
    channel: Channel,
    final_address_self: Address,
    final_address_other: Address,
}
pub struct FinalState(Transaction);

impl FinalState {
    pub fn into_transaction(self) -> Transaction {
        self.0
    }
}

impl From<Channel> for State0 {
    fn from(channel: Channel) -> Self {
        Self(channel)
    }
}

pub struct Message0 {
    final_address: Address,
}

#[derive(Debug)]
pub struct Message1 {
    close_transaction: CloseTransaction,
    sig_close_transaction: Signature,
}

impl State0 {
    pub fn compose(&self, final_address: Address) -> Message0 {
        Message0 { final_address }
    }

    pub fn interpret(
        self,
        final_address_self: Address,
        Message0 {
            final_address: final_address_other,
        }: Message0,
    ) -> State1 {
        State1 {
            channel: self.0,
            final_address_self,
            final_address_other,
        }
    }
}

impl State1 {
    pub fn compose(&self) -> anyhow::Result<Message1> {
        let (amount_a, ownership_a) = self.channel.current_state.signed_TX_s.outputs().a;
        let (amount_b, ownership_b) = self.channel.current_state.signed_TX_s.outputs().b;

        let (output_a, output_b) = if ownership_a == self.channel.x_self.public() {
            (
                (amount_a, self.final_address_self.clone()),
                (amount_b, self.final_address_other.clone()),
            )
        } else if ownership_b == self.channel.x_self.public() {
            (
                (amount_a, self.final_address_other.clone()),
                (amount_b, self.final_address_self.clone()),
            )
        } else {
            anyhow::bail!("No valid output found")
        };

        let close_transaction = CloseTransaction::new(&self.channel.TX_f_body, output_a, output_b);

        let sig_close_transaction = close_transaction.sign_once(self.channel.x_self.clone());

        Ok(Message1 {
            close_transaction,
            sig_close_transaction,
        })
    }

    pub fn interpret(
        self,
        Message1 {
            close_transaction,
            sig_close_transaction: sig_close_transaction_other,
        }: Message1,
    ) -> anyhow::Result<FinalState> {
        // in a real application we would double check the amounts
        let sig_close_transaction_self = close_transaction.sign_once(self.channel.x_self.clone());
        let close_transaction = close_transaction.add_signatures(
            (self.channel.x_self.public(), sig_close_transaction_self),
            (self.channel.X_other, sig_close_transaction_other),
        )?;
        Ok(FinalState(close_transaction))
    }
}
