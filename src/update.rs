use crate::{
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    transaction::{CommitTransaction, SplitTransaction},
    ChannelBalance,
};
use anyhow::bail;
use bitcoin::{Amount, Txid};
use ecdsa_fun::adaptor::EncryptedSignature;
use std::collections::HashMap;

pub struct Message0 {
    proposed_balance: Balance,
    time_lock: u32,
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Message1 {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

pub struct Party0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
}

pub struct RevokedState {
    channel_state: ChannelState,
    r_other: RevocationSecretKey,
}

pub struct ChannelState {
    TX_c: CommitTransaction,
    /// Encrypted signature sent to the counterparty. If the
    /// counterparty decrypts it with their own `PublishingSecretKey`
    /// and uses it to sign and broadcast `TX_c`, we will be able to
    /// extract their `PublishingSecretKey` by using
    /// `recover_decryption_key`. If said `TX_c` was already revoked,
    /// we can use it with the `RevocationSecretKey` to punish them.
    encsig_TX_c_self: EncryptedSignature,
    /// Encrypted signature received from the counterparty. It can be
    /// decrypted using our `PublishingSecretkey` and used to sign
    /// `TX_c`. Keep in mind, that publishing a revoked `TX_c` will
    /// allow the counterparty to punish us.
    encsig_TX_c_other: EncryptedSignature,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    /// Signed split transaction.
    TX_s: SplitTransaction,
}

impl Party0 {
    pub fn propose_channel_update(
        self,
        update: ChannelUpdate,
        time_lock: u32,
    ) -> anyhow::Result<(Sender1, Message0)> {
        let current_balance = self.balance()?;
        let proposed_balance = current_balance.apply(update)?;

        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        let state = Sender1 {
            x_self: self.x_self,
            X_other: self.X_other,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: r_self.clone(),
            y_self: y_self.clone(),
            proposed_balance,
            time_lock,
        };

        let message = Message0 {
            proposed_balance,
            time_lock,
            R: r_self.public(),
            Y: y_self.public(),
        };

        Ok((state, message))
    }

    // QUESTION: Should we verify that the channel state is the same
    // for both parties?
    pub fn receive_channel_update(
        self,
        Message0 {
            proposed_balance,
            time_lock,
            R: R_other,
            Y: Y_other,
        }: Message0,
    ) -> anyhow::Result<(Receiver1, Message1)> {
        // NOTE: A real application would also verify that the amount
        // provided by the other party is satisfactory, together with
        // the time_lock

        let r_self = RevocationKeyPair::new_random();
        let y_self = PublishingKeyPair::new_random();

        let state = Receiver1 {
            x_self: self.x_self,
            X_other: self.X_other,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            r_self: r_self.clone(),
            R_other,
            y_self: y_self.clone(),
            Y_other,
            proposed_balance,
            time_lock,
        };

        let message = Message1 {
            R: r_self.public(),
            Y: y_self.public(),
        };

        Ok((state, message))
    }

    fn balance(&self) -> anyhow::Result<Balance> {
        let channel_balance = self.current_state.TX_s.balance();

        match channel_balance {
            ChannelBalance {
                a: (ours, X_a),
                b: (theirs, X_b),
            } if X_a == self.x_self.public() && X_b == self.X_other => Ok(Balance { ours, theirs }),
            ChannelBalance {
                a: (theirs, X_a),
                b: (ours, X_b),
            } if X_a == self.X_other && X_b == self.x_self.public() => Ok(Balance { ours, theirs }),
            _ => bail!("split transaction does not pay to X_self and X_other"),
        }
    }
}

pub struct Sender1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
    proposed_balance: Balance,
    time_lock: u32,
}

impl Sender1 {
    pub fn receive(
        self,
        Message1 {
            R: R_other,
            Y: Y_other,
        }: Message1,
    ) {
    }
}

pub struct Receiver1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    proposed_balance: Balance,
    time_lock: u32,
}

#[derive(Clone, Copy)]
struct Balance {
    ours: Amount,
    theirs: Amount,
}

pub enum ChannelUpdate {
    Pay(Amount),
    Receive(Amount),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid channel update")]
pub struct InvalidChannelUpdate;

impl Balance {
    fn apply(self, update: ChannelUpdate) -> anyhow::Result<Balance> {
        let (new_ours, new_theirs) = match update {
            ChannelUpdate::Pay(amount) => {
                let new_ours = self.ours.checked_sub(amount);
                let new_theirs = self.theirs.checked_add(amount);

                (new_ours, new_theirs)
            }
            ChannelUpdate::Receive(amount) => {
                let new_ours = self.ours.checked_add(amount);
                let new_theirs = self.theirs.checked_sub(amount);

                (new_ours, new_theirs)
            }
        };

        match (new_ours, new_theirs) {
            (Some(ours), Some(theirs)) if ours >= Amount::ZERO && theirs >= Amount::ZERO => {
                Ok(Balance { ours, theirs })
            }
            _ => bail!(InvalidChannelUpdate),
        }
    }
}
