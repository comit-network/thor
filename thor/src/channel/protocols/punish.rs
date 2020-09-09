use crate::{
    keys::OwnershipKeyPair, transaction::PunishTransaction, RevokedState, StandardChannelState,
};
use bitcoin::{Address, Transaction};

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("transaction cannot be punished")]
struct NotOldCommitTransaction;

pub(in crate::channel) fn build_punish_transaction(
    x_self: &OwnershipKeyPair,
    revoked_states: &[RevokedState],
    final_address: Address,
    old_commit_transaction: Transaction,
) -> anyhow::Result<PunishTransaction> {
    let (channel_state, r_other) = revoked_states
        .iter()
        .map(|state| {
            (
                StandardChannelState::from(state.channel_state.clone()),
                state.r_other.clone(),
            )
        })
        .find(|(state, _)| state.TX_c.txid() == old_commit_transaction.txid())
        .ok_or_else(|| NotOldCommitTransaction)?;

    let encsig_TX_c_self = channel_state.encsign_TX_c_self(x_self);

    let StandardChannelState { TX_c, Y_other, .. } = channel_state;

    let TX_p = PunishTransaction::new(
        x_self,
        final_address,
        &TX_c,
        &encsig_TX_c_self,
        &r_other.into(),
        Y_other,
        old_commit_transaction,
    )?;

    Ok(TX_p)
}
