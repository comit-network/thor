//! # Channel update protocol
//!
//! Alice proposes a channel update to the counterparty.
//!
//! Alice: Channel --> AliceState0 --> State1 --> State2 --> State3 --> Channel
//!
//! Counterparty: Channel --> State1 --> State2 --> State3 --> Channel

use crate::{
    create,
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    signature::{verify_encsig, verify_sig},
    transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
    ChannelBalance, ChannelState, RevokedState,
};
use anyhow::{bail, Context};
use bitcoin::Amount;
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

/// First message of the channel update protocol.
pub struct ChannelUpdateProposal {
    proposed_balance: GlobalBalance,
    time_lock: u32,
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

/// Second message of the channel update protocol.
pub struct ChannelUpdateAccept {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

/// Third message of the channel update protocol.
pub struct ShareSplitSignature {
    sig_TX_s: Signature,
}

/// Fourth message of the channel update protocol.
pub struct ShareCommitEncryptedSignature {
    encsig_TX_c: EncryptedSignature,
}

/// Fifth and last message of the channel update protocol.
pub struct RevealRevocationSecretKey {
    r: RevocationSecretKey,
}

pub struct Channel {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
}

impl Channel {
    pub fn new(party: create::Party6) -> Self {
        Self {
            x_self: party.x_self,
            X_other: party.X_other,
            TX_f_body: party.TX_f_body,
            current_state: ChannelState {
                TX_c: party.TX_c,
                encsig_TX_c_self: party.encsig_TX_c_self,
                encsig_TX_c_other: party.encsig_TX_c_other,
                r_self: party.r_self,
                R_other: party.R_other,
                y_self: party.y_self,
                Y_other: party.Y_other,
                signed_TX_s: party.signed_TX_s,
            },
            revoked_states: Vec::new(),
        }
    }

    pub fn compose(
        self,
        update: ChannelUpdate,
        time_lock: u32,
    ) -> anyhow::Result<(AliceState0, ChannelUpdateProposal)> {
        let LocalBalance { ours, theirs } = self.balance()?;
        let proposed_balance = GlobalBalance {
            sender: ours,
            receiver: theirs,
        }
        .apply(update)?;

        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        let state = AliceState0 {
            x_self: self.x_self,
            X_other: self.X_other,
            TX_f: self.TX_f_body,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: r_self.clone(),
            y_self: y_self.clone(),
            proposed_balance,
            time_lock,
        };

        let message = ChannelUpdateProposal {
            proposed_balance,
            time_lock,
            R: r_self.public(),
            Y: y_self.public(),
        };

        Ok((state, message))
    }

    // QUESTION: Should we verify that the channel state is the same
    // for both parties?
    pub fn interpret(
        self,
        ChannelUpdateProposal {
            proposed_balance:
                GlobalBalance {
                    sender: balance_other,
                    receiver: balance_self,
                },
            time_lock,
            R: R_other,
            Y: Y_other,
        }: ChannelUpdateProposal,
    ) -> anyhow::Result<(State1, ChannelUpdateAccept)> {
        // NOTE: A real application would verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock

        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        let TX_c = CommitTransaction::new(
            &self.TX_f_body,
            (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            (self.x_self.public(), r_self.public(), y_self.public()),
            time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(self.x_self.clone(), Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, ChannelBalance {
            a: (balance_other, self.X_other.clone()),
            b: (balance_self, self.x_self.public()),
        });
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        let state = State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            TX_f: self.TX_f_body,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: r_self.clone(),
            R_other,
            y_self: y_self.clone(),
            Y_other,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        };

        let message = ChannelUpdateAccept {
            R: r_self.public(),
            Y: y_self.public(),
        };

        Ok((state, message))
    }

    pub fn balance(&self) -> anyhow::Result<LocalBalance> {
        let channel_balance = self.current_state.signed_TX_s.balance();

        match channel_balance {
            ChannelBalance {
                a: (ours, X_a),
                b: (theirs, X_b),
            } if X_a == self.x_self.public() && X_b == self.X_other => {
                Ok(LocalBalance { ours, theirs })
            }
            ChannelBalance {
                a: (theirs, X_a),
                b: (ours, X_b),
            } if X_a == self.X_other && X_b == self.x_self.public() => {
                Ok(LocalBalance { ours, theirs })
            }
            _ => bail!("split transaction does not pay to X_self and X_other"),
        }
    }
}

/// A party who has sent a `ChannelUpdateProposal` and is waiting for
/// confirmation.
pub struct AliceState0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    proposed_balance: GlobalBalance,
    time_lock: u32,
}

impl AliceState0 {
    pub fn interpret(
        self,
        ChannelUpdateAccept {
            R: R_other,
            Y: Y_other,
        }: ChannelUpdateAccept,
    ) -> anyhow::Result<State1> {
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

        let GlobalBalance {
            sender: balance_self,
            receiver: balance_other,
        } = self.proposed_balance;
        let TX_s = SplitTransaction::new(&TX_c, ChannelBalance {
            a: (balance_self, self.x_self.public()),
            b: (balance_other, self.X_other.clone()),
        });
        let sig_TX_s_self = TX_s.sign_once(self.x_self.clone());

        Ok(State1 {
            x_self: self.x_self,
            X_other: self.X_other,
            TX_f: self.TX_f,
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
        verify_sig(self.X_other.clone(), &self.TX_s, &sig_TX_s_other)
            .context("failed to verify sig_TX_s sent by counterparty")?;

        self.TX_s.add_signatures(
            (self.x_self.public(), self.sig_TX_s_self),
            (self.X_other.clone(), sig_TX_s_other),
        )?;

        Ok(State2 {
            x_self: self.x_self,
            X_other: self.X_other,
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
            TX_f_body: self.TX_f,
            current_state,
            revoked_states,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct GlobalBalance {
    sender: Amount,
    receiver: Amount,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LocalBalance {
    pub ours: Amount,
    pub theirs: Amount,
}

// NOTE: The protocol proposed in the paper supports updates which add
// new outputs. We exclude that possibility for simplicity.
pub enum ChannelUpdate {
    Pay(Amount),
    Receive(Amount),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid channel update")]
pub struct InvalidChannelUpdate;

impl GlobalBalance {
    /// Apply a `ChannelUpdate` to the current `GlobalBalance`. This is called
    /// to complete a `ChannelUpdateProposal` so we assume the role of the
    /// sender.
    fn apply(self, update: ChannelUpdate) -> anyhow::Result<GlobalBalance> {
        let (new_sender, new_receiver) = match update {
            ChannelUpdate::Pay(amount) => {
                let new_sender = self.sender.checked_sub(amount);
                let new_receiver = self.receiver.checked_add(amount);

                (new_sender, new_receiver)
            }
            ChannelUpdate::Receive(amount) => {
                let new_sender = self.sender.checked_add(amount);
                let new_receiver = self.receiver.checked_sub(amount);

                (new_sender, new_receiver)
            }
        };

        match (new_sender, new_receiver) {
            (Some(sender), Some(receiver))
                if sender >= Amount::ZERO && receiver >= Amount::ZERO =>
            {
                Ok(GlobalBalance { sender, receiver })
            }
            _ => bail!(InvalidChannelUpdate),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transaction::input_psbt;

    #[test]
    fn channel_update() {
        let x_alice = OwnershipKeyPair::new_random();
        let x_bob = OwnershipKeyPair::new_random();

        let r_alice = RevocationKeyPair::new_random();
        let r_bob = RevocationKeyPair::new_random();

        let y_alice = PublishingKeyPair::new_random();
        let y_bob = PublishingKeyPair::new_random();

        let current_balance = GlobalBalance {
            sender: Amount::from_btc(1.0).unwrap(),
            receiver: Amount::from_btc(1.0).unwrap(),
        };

        let alice_input_psbt = input_psbt(current_balance.sender, x_alice.public(), x_bob.public());
        let bob_input_psbt = input_psbt(current_balance.receiver, x_alice.public(), x_bob.public());

        let TX_f = FundingTransaction::new(
            (x_alice.public(), alice_input_psbt, current_balance.sender),
            (x_bob.public(), bob_input_psbt, current_balance.receiver),
        )
        .unwrap();

        let time_lock = 60 * 60;
        let TX_c = CommitTransaction::new(
            &TX_f,
            (x_alice.public(), r_alice.public(), y_alice.public()),
            (x_bob.public(), r_bob.public(), y_bob.public()),
            time_lock,
        )
        .unwrap();

        let TX_s = SplitTransaction::new(&TX_c, ChannelBalance {
            a: (current_balance.sender, x_alice.public()),
            b: (current_balance.receiver, x_bob.public()),
        });

        let alice_encsig = TX_c.encsign_once(x_alice.clone(), y_bob.public());
        let bob_encsig = TX_c.encsign_once(x_bob.clone(), y_alice.public());

        let alice0 = {
            let current_state = ChannelState {
                TX_c: TX_c.clone(),
                encsig_TX_c_self: alice_encsig.clone(),
                encsig_TX_c_other: bob_encsig.clone(),
                r_self: r_alice.clone(),
                R_other: r_bob.public(),
                y_self: y_alice.clone(),
                Y_other: y_bob.public(),
                signed_TX_s: TX_s.clone(),
            };

            Channel {
                x_self: x_alice.clone(),
                X_other: x_bob.public(),
                TX_f_body: TX_f.clone(),
                current_state,
                revoked_states: vec![],
            }
        };

        let bob0 = {
            let current_state = ChannelState {
                TX_c,
                encsig_TX_c_self: bob_encsig,
                encsig_TX_c_other: alice_encsig,
                r_self: r_bob,
                R_other: r_alice.public(),
                y_self: y_bob,
                Y_other: y_alice.public(),
                signed_TX_s: TX_s,
            };

            Channel {
                x_self: x_bob,
                X_other: x_alice.public(),
                TX_f_body: TX_f,
                current_state,
                revoked_states: vec![],
            }
        };

        let channel_update = ChannelUpdate::Pay(Amount::from_btc(0.5).unwrap());
        let time_lock = 60 * 60;

        let (alice1, message0) = alice0.compose(channel_update, time_lock).unwrap();

        let (bob1, message1) = bob0.interpret(message0).unwrap();

        let alice2 = alice1.interpret(message1).unwrap();

        let message2_alice = alice2.compose();
        let message2_bob = bob1.compose();

        let alice3 = alice2.interpret(message2_bob).unwrap();
        let bob2 = bob1.interpret(message2_alice).unwrap();

        let message3_alice = alice3.compose();
        let message3_bob = bob2.compose();

        let alice4 = alice3.interpret(message3_bob).unwrap();
        let bob3 = bob2.interpret(message3_alice).unwrap();

        let message4_alice = alice4.compose();
        let message4_bob = bob3.compose();

        let alice5 = alice4.interpret(message4_bob).unwrap();
        let bob4 = bob3.interpret(message4_alice).unwrap();

        println!("{:?}", alice5.balance().unwrap());
        println!("{:?}", bob4.balance().unwrap());
    }
}
