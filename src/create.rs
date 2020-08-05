use crate::{
    keys::{
        KeyPair, PublicKey, PublishingKeyPair, PublishingPublicKey, RevocationKeyPair,
        RevocationPublicKey,
    },
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
    ChannelState,
};
use bitcoin::{secp256k1, Amount, TxIn};

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

pub struct Party0 {
    x_self: KeyPair,
    tid_self: (TxIn, Amount),
}

impl Party0 {
    pub fn new(tid: (TxIn, Amount)) -> Self {
        let key_pair = KeyPair::new_random();

        Self {
            x_self: key_pair,
            tid_self: tid,
        }
    }

    pub fn next_message(&self) -> Message0 {
        Message0 {
            X: self.x_self.public(),
            tid: self.tid_self.clone(),
        }
    }

    pub fn receive(
        Self { x_self, tid_self }: Self,
        Message0 {
            X: X_other,
            tid: tid_other,
        }: Message0,
    ) -> Party1 {
        let r = RevocationKeyPair::new_random();
        let y = PublishingKeyPair::new_random();

        let TX_f = FundingTransaction::new(
            (x_self.public(), tid_self.clone()),
            (X_other, tid_other.clone()),
        );

        Party1 {
            x_self,
            X_other,
            tid_self,
            tid_other,
            r_self: r,
            y_self: y,
            TX_f,
        }
    }
}

pub struct Party1 {
    x_self: KeyPair,
    X_other: PublicKey,
    tid_self: (TxIn, Amount),
    tid_other: (TxIn, Amount),
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    TX_f: FundingTransaction,
}

impl Party1 {
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
        }: Self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) -> Party2 {
        let TX_c = CommitTransaction::new(
            &TX_f,
            (x_self.public(), r_self.public(), y_self.public()),
            (X_other, R_other, Y_other),
        );

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelState {
                party_0: (tid_self.1, x_self.public()),
                party_1: (tid_other.1, X_other),
            },
        );

        // TODO: Like we do here, for the other transactions we could
        // also generate our signature straight away and save it
        let sig_TX_s_self = todo!("Sign TX_s.digest() using x_self");

        Party2 {
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
        }
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
    sig_TX_s_self: secp256k1::Signature,
}

impl Party2 {
    pub fn new_message(&self) -> Message2 {
        Message2 {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn receive(self, _message: Message2) -> Party3 {
        todo!()
    }
}

pub struct Party3;
