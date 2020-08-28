use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    transaction::{CommitTransaction, FundOutput, SplitTransaction},
    Balance, Channel, ChannelState, SplitOutput,
};
use anyhow::Context;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

pub use crate::transaction::FundingTransaction;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message0 {
    X: OwnershipPublicKey,
    final_address: Address,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message1 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    input_psbt: PartiallySignedTransaction,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message2 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message3 {
    sig_TX_s: Signature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message4 {
    encsig_TX_c: EncryptedSignature,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct Message5 {
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::serde::partially_signed_transaction")
    )]
    TX_f_signed_once: PartiallySignedTransaction,
}

#[derive(Debug)]
pub struct State0 {
    x_self: OwnershipKeyPair,
    final_address_self: Address,
    balance: Balance,
    time_lock: u32,
}

#[async_trait::async_trait]
pub trait BuildFundingPSBT {
    async fn build_funding_psbt(
        &self,
        output_address: Address,
        output_amount: Amount,
    ) -> anyhow::Result<PartiallySignedTransaction>;
}

impl State0 {
    pub fn new(balance: Balance, time_lock: u32, final_address: Address) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            balance,
            final_address_self: final_address,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            final_address: self.final_address_self.clone(),
        }
    }

    pub async fn receive(
        self,
        Message0 {
            X: X_other,
            final_address: final_address_other,
        }: Message0,
        wallet: &impl BuildFundingPSBT,
    ) -> anyhow::Result<State1> {
        let fund_output = FundOutput::new([self.x_self.public(), X_other.clone()]);
        let input_psbt_self = wallet
            .build_funding_psbt(fund_output.address(), self.balance.ours)
            .await?;

        Ok(State1 {
            x_self: self.x_self,
            X_other,
            final_address_self: self.final_address_self,
            final_address_other,
            balance: self.balance,
            input_psbt_self,
            time_lock: self.time_lock,
        })
    }
}

#[derive(Debug)]
pub struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    input_psbt_self: PartiallySignedTransaction,
    time_lock: u32,
}

impl State1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            input_psbt: self.input_psbt_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message1 {
            input_psbt: input_pstb_other,
        }: Message1,
    ) -> anyhow::Result<State2> {
        let TX_f = FundingTransaction::new(
            [
                (self.x_self.public(), self.input_psbt_self.clone()),
                (self.X_other.clone(), input_pstb_other),
            ],
            self.balance.ours + self.balance.theirs,
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(State2 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            balance: self.balance,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

#[derive(Clone, Debug)]
pub struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    balance: Balance,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl State2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            R: R_other,
            Y: Y_other,
        }: Message2,
    ) -> anyhow::Result<Party3> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            [
                (
                    self.x_self.public(),
                    self.r_self.public(),
                    self.y_self.public(),
                ),
                (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            ],
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other.clone());

        let split_outputs = vec![
            SplitOutput::Balance {
                amount: self.balance.ours,
                address: self.final_address_self.clone(),
            },
            SplitOutput::Balance {
                amount: self.balance.theirs,
                address: self.final_address_other.clone(),
            },
        ];
        let TX_s = SplitTransaction::new(&TX_c, split_outputs.clone())?;
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

#[derive(Debug)]
pub struct Party3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl Party3 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(
        mut self,
        Message3 {
            sig_TX_s: sig_TX_s_other,
        }: Message3,
    ) -> anyhow::Result<Party4> {
        self.TX_s
            .verify_sig(self.X_other.clone(), &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(Party4 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs: self.split_outputs,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
        })
    }
}

#[derive(Debug)]
pub struct Party4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl Party4 {
    pub fn next_message(&self) -> Message4 {
        Message4 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message4 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message4,
    ) -> anyhow::Result<Party5> {
        self.TX_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
                &encsig_TX_c_other,
            )
            .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(Party5 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            split_outputs: self.split_outputs,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
        })
    }
}

#[derive(Debug)]
pub struct Party5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait::async_trait]
pub trait SignFundingPSBT {
    async fn sign_funding_psbt(
        &self,
        psbt: PartiallySignedTransaction,
    ) -> anyhow::Result<PartiallySignedTransaction>;
}

impl Party5 {
    pub async fn next_message(&self, wallet: &impl SignFundingPSBT) -> anyhow::Result<Message5> {
        let TX_f_signed_once = wallet
            .sign_funding_psbt(self.TX_f.clone().into_psbt()?)
            .await?;

        Ok(Message5 { TX_f_signed_once })
    }

    /// Returns the Channel and the transaction to broadcast.
    pub async fn receive(
        self,
        Message5 { TX_f_signed_once }: Message5,
        wallet: &impl SignFundingPSBT,
    ) -> anyhow::Result<(Channel, Transaction)> {
        let signed_TX_f = wallet.sign_funding_psbt(TX_f_signed_once).await?;
        let signed_TX_f = signed_TX_f.extract_tx();

        Ok((
            Channel {
                x_self: self.x_self,
                X_other: self.X_other,
                final_address_self: self.final_address_self,
                final_address_other: self.final_address_other,
                TX_f_body: self.TX_f,
                current_state: ChannelState {
                    split_outputs: self.split_outputs,
                    TX_c: self.TX_c,
                    encsig_TX_c_self: self.encsig_TX_c_self,
                    encsig_TX_c_other: self.encsig_TX_c_other,
                    r_self: self.r_self,
                    R_other: self.R_other,
                    y_self: self.y_self,
                    Y_other: self.Y_other,
                    signed_TX_s: self.signed_TX_s,
                },
                revoked_states: vec![],
            },
            signed_TX_f,
        ))
    }
}
