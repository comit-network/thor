use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{CommitTransaction, FundOutput, SplitTransaction},
    SplitOutputs,
};
use anyhow::Context;
use bitcoin::{util::psbt::PartiallySignedTransaction, Address, Amount, Transaction};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

pub use crate::transaction::FundingTransaction;

pub enum Message {
    Message0(Message0),
    Message1(Message1),
    Message2(Message2),
    Message3(Message3),
    Message4(Message4),
    Message5(Message5),
}

pub struct Message0 {
    X: OwnershipPublicKey,
    fund_amount: Amount,
    time_lock: u32,
}

pub struct Message1 {
    tid: PartiallySignedTransaction,
}

pub struct Message2 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Message3 {
    sig_TX_s: Signature,
}

pub struct Message4 {
    encsig_TX_c: EncryptedSignature,
}

pub struct Message5 {
    TX_f_signed_once: PartiallySignedTransaction,
}

pub struct Alice0 {
    x_self: OwnershipKeyPair,
    fund_amount_self: Amount,
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

impl Alice0 {
    pub fn new(fund_amount: Amount, time_lock: u32) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            fund_amount_self: fund_amount,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            fund_amount: self.fund_amount_self,
            time_lock: self.time_lock,
        }
    }

    pub async fn receive(
        self,
        Message0 {
            X: X_other,
            fund_amount: fund_amount_other,
            time_lock: time_lock_other,
        }: Message0,
        wallet: &impl BuildFundingPSBT,
    ) -> anyhow::Result<Alice1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock
        check_timelocks(self.time_lock, time_lock_other)?;

        let fund_output = FundOutput::new(self.x_self.public(), X_other.clone());
        let tid_self = wallet
            .build_funding_psbt(fund_output.address(), self.fund_amount_self)
            .await?;

        Ok(Alice1 {
            x_self: self.x_self,
            X_other,
            fund_amount_self: self.fund_amount_self,
            fund_amount_other,
            tid_self,
            time_lock: self.time_lock,
        })
    }
}

pub struct Bob0 {
    x_self: OwnershipKeyPair,
    fund_amount_self: Amount,
    time_lock: u32,
}

impl Bob0 {
    pub fn new(fund_amount: Amount, time_lock: u32) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            fund_amount_self: fund_amount,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            fund_amount: self.fund_amount_self,
            time_lock: self.time_lock,
        }
    }

    pub async fn receive(
        self,
        Message0 {
            X: X_other,
            fund_amount: fund_amount_other,
            time_lock: time_lock_other,
        }: Message0,
        wallet: &impl BuildFundingPSBT,
    ) -> anyhow::Result<Bob1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock
        check_timelocks(self.time_lock, time_lock_other)?;

        let fund_output = FundOutput::new(X_other.clone(), self.x_self.public());
        let tid_self = wallet
            .build_funding_psbt(fund_output.address(), self.fund_amount_self)
            .await?;

        Ok(Bob1 {
            x_self: self.x_self,
            X_other,
            fund_amount_self: self.fund_amount_self,
            fund_amount_other,
            tid_self,
            time_lock: self.time_lock,
        })
    }
}

pub struct Alice1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    fund_amount_self: Amount,
    fund_amount_other: Amount,
    tid_self: PartiallySignedTransaction,
    time_lock: u32,
}

impl Alice1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(self, Message1 { tid: tid_other }: Message1) -> anyhow::Result<Alice2> {
        let TX_f = FundingTransaction::new(
            (
                self.x_self.public(),
                self.tid_self.clone(),
                self.fund_amount_self,
            ),
            (self.X_other.clone(), tid_other, self.fund_amount_other),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(Alice2 {
            x_self: self.x_self,
            X_other: self.X_other,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

pub struct Bob1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    fund_amount_self: Amount,
    fund_amount_other: Amount,
    tid_self: PartiallySignedTransaction,
    time_lock: u32,
}

impl Bob1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(self, Message1 { tid: tid_other }: Message1) -> anyhow::Result<Bob2> {
        let TX_f = FundingTransaction::new(
            (self.X_other.clone(), tid_other, self.fund_amount_other),
            (
                self.x_self.public(),
                self.tid_self.clone(),
                self.fund_amount_self,
            ),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(Bob2 {
            x_self: self.x_self,
            X_other: self.X_other,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("time_locks are not equal")]
pub struct IncompatibleTimeLocks;

fn check_timelocks(time_lock_self: u32, time_lock_other: u32) -> Result<(), IncompatibleTimeLocks> {
    if time_lock_self != time_lock_other {
        Err(IncompatibleTimeLocks)
    } else {
        Ok(())
    }
}

pub struct Alice2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Alice2 {
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
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, SplitOutputs {
            a: (self.TX_f.amount_a(), self.x_self.public()),
            b: (self.TX_f.amount_b(), self.X_other.clone()),
        });
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
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

pub struct Bob2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Bob2 {
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
            (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, SplitOutputs {
            a: (self.TX_f.amount_a(), self.X_other.clone()),
            b: (self.TX_f.amount_b(), self.x_self.public()),
        });

        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            sig_TX_s_self,
            encsig_TX_c_self,
        })
    }
}

pub struct Party3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
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
        verify_sig(self.X_other.clone(), &self.TX_s, &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(Party4 {
            x_self: self.x_self,
            X_other: self.X_other,
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

pub struct Party4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
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
        verify_encsig(
            self.X_other.clone(),
            self.y_self.public(),
            &self.TX_c,
            &encsig_TX_c_other,
        )
        .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(Party5 {
            x_self: self.x_self,
            X_other: self.X_other,
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

pub struct Party5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
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

    pub async fn receive(
        self,
        Message5 { TX_f_signed_once }: Message5,
        wallet: &impl SignFundingPSBT,
    ) -> anyhow::Result<Party6> {
        let signed_TX_f = wallet.sign_funding_psbt(TX_f_signed_once).await?;
        let signed_TX_f = signed_TX_f.extract_tx();

        Ok(Party6 {
            x_self: self.x_self,
            X_other: self.X_other,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_f_body: self.TX_f,
            signed_TX_f,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other: self.encsig_TX_c_other,
        })
    }
}

/// A party which has reached this state is now able to safely broadcast the
/// `FundingTransaction` in order to open the channel.
#[allow(dead_code)]
pub struct Party6 {
    pub x_self: OwnershipKeyPair,
    pub X_other: OwnershipPublicKey,
    pub r_self: RevocationKeyPair,
    pub R_other: RevocationPublicKey,
    pub y_self: PublishingKeyPair,
    pub Y_other: PublishingPublicKey,
    // TODO: Use `FundingTransaction` or introduce `SignedFundingTransaction` type. This is
    // necessary because other protocols will still need functionality defined on
    // `FundingTransaction` even after the channel has been created
    pub TX_f_body: FundingTransaction,
    pub signed_TX_f: Transaction,
    pub TX_c: CommitTransaction,
    pub signed_TX_s: SplitTransaction,
    pub encsig_TX_c_self: EncryptedSignature,
    pub encsig_TX_c_other: EncryptedSignature,
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{OutPoint, Script, TxIn, TxOut};

    struct MockWallet;

    #[async_trait::async_trait]
    impl BuildFundingPSBT for MockWallet {
        async fn build_funding_psbt(
            &self,
            output_address: Address,
            output_amount: Amount,
        ) -> anyhow::Result<PartiallySignedTransaction> {
            let transaction = Transaction {
                version: 2,
                lock_time: 0,
                input: vec![TxIn {
                    previous_output: OutPoint::default(),
                    script_sig: Script::new(),
                    sequence: 0xFFFF_FFFF,
                    witness: Vec::new(),
                }],
                output: vec![TxOut {
                    value: output_amount.as_sat(),
                    script_pubkey: output_address.script_pubkey(),
                }],
            };

            PartiallySignedTransaction::from_unsigned_tx(transaction)
                .map_err(|_| anyhow::anyhow!("could not convert transaction into psbt"))
        }
    }

    #[async_trait::async_trait]
    impl SignFundingPSBT for MockWallet {
        async fn sign_funding_psbt(
            &self,
            transaction: PartiallySignedTransaction,
        ) -> anyhow::Result<PartiallySignedTransaction> {
            Ok(transaction)
        }
    }

    #[tokio::test]
    async fn channel_creation() {
        let time_lock = 3;

        let (channel_balance_alice, channel_balance_bob) = { (Amount::ONE_BTC, Amount::ONE_BTC) };

        let alice0 = Alice0::new(channel_balance_alice, time_lock);
        let bob0 = Bob0::new(channel_balance_bob, time_lock);

        let message0_alice = alice0.next_message();
        let message0_bob = bob0.next_message();

        let alice_wallet = MockWallet;
        let bob_wallet = MockWallet;

        let alice1 = alice0.receive(message0_bob, &alice_wallet).await.unwrap();
        let bob1 = bob0.receive(message0_alice, &bob_wallet).await.unwrap();

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

        let message5_alice = alice5.next_message(&alice_wallet).await.unwrap();
        let message5_bob = bob5.next_message(&bob_wallet).await.unwrap();

        let alice6 = alice5.receive(message5_bob, &alice_wallet).await.unwrap();
        let bob6 = bob5.receive(message5_alice, &bob_wallet).await.unwrap();

        assert_eq!(alice6.signed_TX_f, bob6.signed_TX_f);

        assert_eq!(alice6.TX_c, bob6.TX_c);

        assert_eq!(alice6.encsig_TX_c_self, bob6.encsig_TX_c_other);

        assert_eq!(alice6.encsig_TX_c_other, bob6.encsig_TX_c_self);

        assert_eq!(alice6.signed_TX_s, bob6.signed_TX_s);
    }
}
