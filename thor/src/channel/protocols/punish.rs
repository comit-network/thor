use crate::{
    channel::{RevokedState, StandardChannelState},
    keys::OwnershipKeyPair,
    transaction::PunishTransaction,
};
use anyhow::Result;
use bitcoin::{Address, Transaction};

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("transaction cannot be punished")]
pub struct NotOldCommitTransaction;

pub(crate) fn punish(
    x_self: &OwnershipKeyPair,
    revoked_states: &[RevokedState],
    final_address: Address,
    old_commit_transaction: Transaction,
) -> Result<PunishTransaction> {
    let (channel_state, r_other) = revoked_states
        .iter()
        .map(|state| {
            (
                StandardChannelState::from(state.channel_state.clone()),
                state.r_other.clone(),
            )
        })
        .find(|(state, _)| state.tx_c.txid() == old_commit_transaction.txid())
        .ok_or_else(|| NotOldCommitTransaction)?;

    let encsig_tx_c_self = channel_state.encsign_tx_c_self(x_self);

    let StandardChannelState { tx_c, Y_other, .. } = channel_state;

    let tx_p = PunishTransaction::new(
        x_self,
        final_address,
        &tx_c,
        &encsig_tx_c_self,
        &r_other.into(),
        Y_other,
        old_commit_transaction,
    )?;

    Ok(tx_p)
}
