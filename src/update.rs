//! # Channel update protocol
//!
//! Alice proposes a channel update to Bob.
//!
//! Alice: State0(Channel) --> AliceState0 --> State1 --> State2 --> State3 -->
//! Channel
//!
//! Bob: State0(Channel) --> State1 --> State2 --> State3 --> Channel

use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
    Balance, Channel, ChannelState, RevokedState, SplitOutputs,
};
use anyhow::Context;
use bitcoin::Address;
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

/// First message of the channel update protocol.
#[derive(Debug)]
pub struct ShareKeys {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

/// Third message of the channel update protocol.
#[derive(Debug)]
pub struct ShareSplitSignature {
    sig_TX_s: Signature,
}

/// Fourth message of the channel update protocol.
#[derive(Debug)]
pub struct ShareCommitEncryptedSignature {
    encsig_TX_c: EncryptedSignature,
}

/// Fifth and last message of the channel update protocol.
#[derive(Debug)]
pub struct RevealRevocationSecretKey {
    r: RevocationSecretKey,
}

pub struct Alice0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    updated_balance: Balance,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
}

impl Alice0 {
    pub fn new(channel: Channel, updated_balance: Balance, time_lock: u32) -> Self {
        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        Self {
            x_self: channel.x_self,
            X_other: channel.X_other,
            final_address_self: channel.final_address_self,
            final_address_other: channel.final_address_other,
            TX_f_body: channel.TX_f_body,
            current_state: channel.current_state,
            revoked_states: channel.revoked_states,
            updated_balance,
            time_lock,
            r_self,
            y_self,
        }
    }

    pub fn compose(&self) -> ShareKeys {
        ShareKeys {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn interpret(
        self,
        ShareKeys {
            R: R_other,
            Y: Y_other,
        }: ShareKeys,
    ) -> anyhow::Result<State1> {
        let TX_c = CommitTransaction::new(
            &self.TX_f_body,
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
            a: (self.updated_balance.ours, self.final_address_self.clone()),
            b: (
                self.updated_balance.theirs,
                self.final_address_other.clone(),
            ),
        });
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f: self.TX_f_body,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

pub struct Bob0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    updated_balance: Balance,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
}

impl Bob0 {
    pub fn new(channel: Channel, updated_balance: Balance, time_lock: u32) -> Self {
        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        Self {
            x_self: channel.x_self,
            X_other: channel.X_other,
            final_address_self: channel.final_address_self,
            final_address_other: channel.final_address_other,
            TX_f_body: channel.TX_f_body,
            current_state: channel.current_state,
            revoked_states: channel.revoked_states,
            updated_balance,
            time_lock,
            r_self,
            y_self,
        }
    }

    pub fn compose(&self) -> ShareKeys {
        ShareKeys {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub fn interpret(
        self,
        ShareKeys {
            R: R_other,
            Y: Y_other,
        }: ShareKeys,
    ) -> anyhow::Result<State1> {
        let TX_c = CommitTransaction::new(
            &self.TX_f_body,
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
            a: (
                self.updated_balance.theirs,
                self.final_address_other.clone(),
            ),
            b: (self.updated_balance.ours, self.final_address_self.clone()),
        });
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f: self.TX_f_body,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        })
    }
}

/// A party who has agreed on the terms of a channel update and is
/// ready to start exchanging signatures.
pub struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_c: CommitTransaction,
    TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    sig_TX_s_self: Signature,
}

impl State1 {
    pub fn compose(&self) -> ShareSplitSignature {
        ShareSplitSignature {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub fn interpret(
        mut self,
        ShareSplitSignature {
            sig_TX_s: sig_TX_s_other,
        }: ShareSplitSignature,
    ) -> anyhow::Result<State2> {
        verify_sig(self.X_other.clone(), &self.TX_s.digest(), &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(State2 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f: self.TX_f,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_c: self.TX_c,
            signed_TX_s: self.TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
        })
    }
}

/// A party who has exchanged signatures for the `SplitTransaction`
/// and is ready to start exchanging encrypted signatures for the
/// `CommitTransaction`.
pub struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl State2 {
    pub fn compose(&self) -> ShareCommitEncryptedSignature {
        ShareCommitEncryptedSignature {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub fn interpret(
        self,
        ShareCommitEncryptedSignature {
            encsig_TX_c: encsig_TX_c_other,
        }: ShareCommitEncryptedSignature,
    ) -> anyhow::Result<State3> {
        verify_encsig(
            self.X_other.clone(),
            self.y_self.public(),
            &self.TX_c,
            &encsig_TX_c_other,
        )
        .context("failed to verify encsig_TX_c sent by counterparty")?;

        Ok(State3 {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f: self.TX_f,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            TX_c: self.TX_c,
            signed_TX_s: self.signed_TX_s,
            encsig_TX_c_self: self.encsig_TX_c_self,
            encsig_TX_c_other,
        })
    }
}

/// A party who has exchanged all necessary signatures to complete a
/// channel update and just needs to collaborate with the counterparty
/// to revoke the previous `CommitTransaction`.
pub struct State3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
    encsig_TX_c_other: EncryptedSignature,
}

impl State3 {
    pub fn compose(&self) -> RevealRevocationSecretKey {
        RevealRevocationSecretKey {
            r: self.current_state.r_self.clone().into(),
        }
    }

    pub fn interpret(
        self,
        RevealRevocationSecretKey { r: r_other }: RevealRevocationSecretKey,
    ) -> anyhow::Result<Channel> {
        self.current_state
            .R_other
            .verify_revocation_secret_key(&r_other)?;

        let revoked_state = RevokedState {
            channel_state: self.current_state,
            r_other,
        };
        let mut revoked_states = self.revoked_states;
        revoked_states.push(revoked_state);

        let current_state = ChannelState {
            TX_c: self.TX_c,
            encsig_TX_c_self: self.encsig_TX_c_other,
            encsig_TX_c_other: self.encsig_TX_c_self,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            signed_TX_s: self.signed_TX_s,
        };

        Ok(Channel {
            x_self: self.x_self,
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f_body: self.TX_f,
            current_state,
            revoked_states,
        })
    }
}
