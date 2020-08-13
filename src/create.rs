use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
    ChannelBalance,
};
use anyhow::{bail, Context};
use bitcoin::{secp256k1, Amount, TxIn};
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};
use std::marker::PhantomData;

pub struct Message0 {
    X: OwnershipPublicKey,
    tid: (TxIn, Amount),
    time_lock: u32,
}

pub struct Message1 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Message2 {
    sig_TX_s: Signature,
}

pub struct Message3 {
    encsig_TX_c: EncryptedSignature,
}

pub struct Message4 {
    TX_f_signed_once: FundingTransaction,
}

pub struct Alice0 {
    x_self: OwnershipKeyPair,
    tid_self: (TxIn, Amount),
    time_lock: u32,
}

impl Alice0 {
    pub fn new(tid_self: (TxIn, Amount), time_lock: u32) -> Self {
        let x_self = OwnershipKeyPair::new_random();

        Self {
            x_self,
            tid_self,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
            time_lock: self.time_lock,
        }
    }

    pub fn receive(
        self,
        Message0 {
            X: X_other,
            tid: tid_other,
            time_lock: time_lock_other,
        }: Message0,
    ) -> anyhow::Result<Alice1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock
        check_timelocks(self.time_lock, time_lock_other)?;

        let TX_f = FundingTransaction::new(
            (self.x_self.public(), self.tid_self.clone()),
            (X_other.clone(), tid_other.clone()),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(Alice1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
            time_lock: self.time_lock,
            r_self: r,
            y_self: y,
            TX_f,
        })
    }
}

pub struct Bob0 {
    x_self: OwnershipKeyPair,
    tid_self: (TxIn, Amount),
    time_lock: u32,
}

impl Bob0 {
    pub fn new(tid_self: (TxIn, Amount), time_lock: u32) -> Self {
        let x_self = OwnershipKeyPair::new_random();
        Self {
            x_self,
            tid_self,
            time_lock,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
            time_lock: self.time_lock,
        }
    }

    pub fn receive(
        self,
        Message0 {
            X: X_other,
            tid: tid_other,
            time_lock: time_lock_other,
        }: Message0,
    ) -> anyhow::Result<Bob1> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory
        check_timelocks(self.time_lock, time_lock_other)?;

        let TX_f = FundingTransaction::new(
            (X_other.clone(), tid_other.clone()),
            (self.x_self.public(), self.tid_self.clone()),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        Ok(Bob1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
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

pub struct Alice1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Alice1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            (self.X_other.clone(), R_other, Y_other.clone()),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other);

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelBalance {
                a: (self.tid_self.1, self.x_self.public()),
                b: (self.tid_other.1, self.X_other.clone()),
            },
        );
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party2 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

pub struct Bob1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Bob1 {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &self.TX_f,
            (self.X_other.clone(), R_other, Y_other.clone()),
            (
                self.x_self.public(),
                self.r_self.public(),
                self.y_self.public(),
            ),
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other);

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelBalance {
                a: (self.tid_other.1, self.X_other.clone()),
                b: (self.tid_self.1, self.x_self.public()),
            },
        );
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(Party2 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c,
            TX_s,
            sig_TX_s_self,
            encsig_TX_c_self,
        })
    }
}

pub struct Party2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl Party2 {
    pub fn next_message(&self) -> Message2 {
        Message2 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message2 {
            sig_TX_s: sig_TX_s_other,
        }: Message2,
    ) -> anyhow::Result<Party3> {
        verify_sig(self.X_other.clone(), &self.TX_s, &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        // TODO: Use sig_TX_s_self and sig_TX_s_other to actually sign
        // the SplitTransaction

        Ok(Party3 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
        })
    }
}

pub struct Party3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl Party3 {
    pub fn next_message(&self) -> Message3 {
        Message3 {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message3 {
            encsig_TX_c: encsig_TX_c_other,
        }: Message3,
    ) -> anyhow::Result<Party4> {
        verify_encsig(
            self.X_other.clone(),
            self.y_self.public(),
            &self.TX_c,
            &encsig_TX_c_other,
        )
        .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(Party4 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            TX_f: self.TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
        })
    }
}

pub struct Party4 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait::async_trait]
pub trait Sign {
    async fn sign(&self, transaction: FundingTransaction) -> anyhow::Result<FundingTransaction>;
}

impl Party4 {
    pub async fn next_message(&self, wallet: impl Sign) -> anyhow::Result<Message4> {
        let TX_f_signed_once = wallet.sign(self.TX_f.clone()).await?;

        Ok(Message4 { TX_f_signed_once })
    }

    pub async fn receive(
        self,
        Message4 { TX_f_signed_once }: Message4,
        wallet: impl Sign,
    ) -> anyhow::Result<Party5> {
        let signed_TX_f = wallet.sign(TX_f_signed_once).await?;

        Ok(Party5 {
            x_self: self.x_self,
            X_other: self.X_other,
            tid_self: self.tid_self,
            tid_other: self.tid_other,
            r_self: self.r_self,
            y_self: self.y_self,
            signed_TX_f,
            TX_c: self.TX_c,
            TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other: self.encsig_TX_c_other,
        })
    }
}

/// A party which has reached this state is now able to safely
/// broadcast the `FundingTransaction` in order to open the channel.
pub struct Party5 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    signed_TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transaction: ")]
    Transaction(#[from] crate::transaction::Error),
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn channel_creation() {
        let time_lock = 60 * 60;

        let alice0 = {
            let input = TxIn::default();
            let amount = Amount::from_sat(1_000);

            Alice0::new((input, amount), time_lock)
        };

        let bob0 = {
            let input = TxIn::default();
            let amount = Amount::from_sat(1_000);

            Bob0::new((input, amount), time_lock)
        };

        let message0_alice = alice0.next_message();
        let message0_bob = bob0.next_message();

        let alice1 = alice0.receive(message0_bob).unwrap();
        let bob1 = bob0.receive(message0_alice).unwrap();

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
    }
}
