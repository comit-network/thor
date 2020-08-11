use crate::{
    keys::{
        KeyPair, PublicKey, PublishingKeyPair, PublishingPublicKey, RevocationKeyPair,
        RevocationPublicKey,
    },
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
    ChannelState,
};
use anyhow::Context;
use bitcoin::{secp256k1, Amount, TxIn};
use std::marker::PhantomData;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct AdaptorSignature;

pub struct Message0 {
    X: PublicKey,
    tid: (TxIn, Amount),
}

pub struct Message1 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Message2 {
    sig_TX_s: secp256k1::Signature,
}

pub struct Message3 {
    sig_TX_c: AdaptorSignature,
}

pub struct Message4 {
    TX_f_signed_once: FundingTransaction,
}

struct Alice;
struct Bob;

pub struct Party0<R> {
    x_self: KeyPair,
    tid_self: (TxIn, Amount),
    phantom: PhantomData<R>,
}

impl Party0<Alice> {
    pub fn new(tid_self: (TxIn, Amount)) -> Self {
        let x_self = KeyPair::new_random();
        Self {
            x_self,
            tid_self,
            phantom: Default::default(),
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message0 {
            X: X_other,
            tid: tid_other,
        }: Message0,
    ) -> anyhow::Result<Party1<Alice>> {
        let TX_f = FundingTransaction::new(
            (self.x_self.public(), self.tid_self.clone()),
            (X_other, tid_other.clone()),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();
        Ok(Party1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
            r_self: r,
            y_self: y,
            TX_f,
            phantom: PhantomData::default(),
        })
    }
}

impl Party0<Bob> {
    pub fn new(tid_self: (TxIn, Amount)) -> Self {
        let x_self = KeyPair::new_random();
        Self {
            x_self,
            tid_self,
            phantom: Default::default(),
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message0 {
            X: X_other,
            tid: tid_other,
        }: Message0,
    ) -> anyhow::Result<Party1<Bob>> {
        let TX_f = FundingTransaction::new(
            (X_other, tid_other.clone()),
            (self.x_self.public(), self.tid_self.clone()),
        )
        .context("failed to build funding transaction")?;

        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();
        Ok(Party1 {
            x_self: self.x_self,
            X_other,
            tid_self: self.tid_self,
            tid_other,
            r_self: r,
            y_self: y,
            TX_f,
            phantom: PhantomData::default(),
        })
    }
}

pub struct Party1<R> {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    phantom: PhantomData<R>,
}

impl Party1<Alice> {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        Self {
            x_self,
            X_other,
            tid_self,
            tid_other,
            r_self,
            y_self,
            TX_f,
            ..
        }: Self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
        time_lock: u32,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &TX_f,
            (x_self.public(), r_self.public(), y_self.public()),
            (X_other, R_other, Y_other),
            time_lock,
        )?;
        let sig_TX_c_self = TX_c.sign_once(x_self.clone(), Y_other)?;

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelState {
                a: (tid_self.1, x_self.public()),
                b: (tid_other.1, X_other),
            },
        );
        let sig_TX_s_self = todo!("Sign TX_s.digest() using x_self");

        Ok(Party2 {
            x_self,
            X_other,
            tid_self,
            tid_other,
            r_self,
            y_self,
            TX_f,
            TX_c,
            TX_s,
            sig_TX_s_self,
            sig_TX_c_self,
        })
    }
}

impl Party1<Bob> {
    pub fn next_message(&self) -> Message1 {
        Message1 {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn receive(
        Self {
            x_self,
            X_other,
            tid_self,
            tid_other,
            r_self,
            y_self,
            TX_f,
            ..
        }: Self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
        time_lock: u32,
    ) -> anyhow::Result<Party2> {
        let TX_c = CommitTransaction::new(
            &TX_f,
            (X_other, R_other, Y_other),
            (x_self.public(), r_self.public(), y_self.public()),
            time_lock,
        )?;
        let sig_TX_c_self = TX_c.sign_once(x_self.clone(), Y_other)?;

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelState {
                a: (tid_other.1, X_other),
                b: (tid_self.1, x_self.public()),
            },
        );
        let sig_TX_s_self = TX_s.sign_once(x_self.clone())?;

        Ok(Party2 {
            x_self,
            X_other,
            tid_self,
            tid_other,
            r_self,
            y_self,
            TX_f,
            TX_c,
            TX_s,
            sig_TX_s_self,
            sig_TX_c_self,
        })
    }
}

pub struct Party2 {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    sig_TX_c_self: AdaptorSignature,
    sig_TX_s_self: secp256k1::Signature,
}

impl Party2 {
    pub fn new_message(&self) -> Message2 {
        Message2 {
            sig_TX_s: self.sig_TX_s_self,
        }
    }

    pub fn receive(
        self,
        Message2 {
            sig_TX_s: sig_TX_s_other,
        }: Message2,
    ) -> anyhow::Result<Party3> {
        todo!("verify sig_TX_s_other is a valid signature on self.TX_s.digest() for self.X_other");

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
            sig_TX_c_self: self.sig_TX_c_self,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other,
        })
    }
}

pub struct Party3 {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    sig_TX_c_self: AdaptorSignature,
    sig_TX_s_self: secp256k1::Signature,
    sig_TX_s_other: secp256k1::Signature,
}

impl Party3 {
    pub fn new_message(&self) -> Message3 {
        Message3 {
            sig_TX_c: self.sig_TX_c_self.clone(),
        }
    }

    pub fn receive(
        self,
        Message3 {
            sig_TX_c: sig_TX_c_other,
        }: Message3,
    ) -> anyhow::Result<Party4> {
        todo!(
            "pVerify sig_TX_c_other is a valid adaptor signature on
             self.TX_c.digest() for self.X_other and self.y_self.public()"
        );

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
            sig_TX_c_self: self.sig_TX_c_self,
            sig_TX_c_other,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other: self.sig_TX_s_other,
        })
    }
}

pub struct Party4 {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    sig_TX_c_self: AdaptorSignature,
    sig_TX_c_other: AdaptorSignature,
    sig_TX_s_self: secp256k1::Signature,
    sig_TX_s_other: secp256k1::Signature,
}

/// Sign one of the inputs of the `FundingTransaction`.
#[async_trait::async_trait]
pub trait Sign {
    async fn sign(&self, transaction: FundingTransaction) -> anyhow::Result<FundingTransaction>;
}

impl Party4 {
    pub async fn new_message(&self, wallet: impl Sign) -> anyhow::Result<Message4> {
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
            sig_TX_c_self: self.sig_TX_c_self,
            sig_TX_c_other: self.sig_TX_c_other,
            sig_TX_s_self: self.sig_TX_s_self,
            sig_TX_s_other: self.sig_TX_s_other,
        })
    }
}

/// A party which has reached this state is now able to safely
/// broadcast the `FundingTransaction` in order to open the channel.
pub struct Party5 {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    signed_TX_f: FundingTransaction,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    sig_TX_c_self: AdaptorSignature,
    sig_TX_c_other: AdaptorSignature,
    sig_TX_s_self: secp256k1::Signature,
    sig_TX_s_other: secp256k1::Signature,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Transaction: ")]
    Transaction(#[from] crate::transaction::Error),
}
