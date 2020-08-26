use crate::{
    keys::OwnershipKeyPair, protocols::Result, transaction::PunishTransaction, ChannelState, Error,
    RevokedState,
};
use bitcoin::{Address, Transaction};

pub fn punish(
    x_self: &OwnershipKeyPair,
    revoked_states: &[RevokedState],
    final_address: Address,
    old_commit_transaction: Transaction,
) -> Result<PunishTransaction> {
    let RevokedState {
        channel_state:
            ChannelState {
                TX_c,
                Y_other,
                encsig_TX_c_self,
                ..
            },
        r_other,
    } = revoked_states
        .iter()
        .find(|state| state.channel_state.TX_c.txid() == old_commit_transaction.txid())
        .ok_or_else(|| Error::NotOldCommitTransaction)?;

    let TX_p = PunishTransaction::new(
        x_self,
        final_address,
        &TX_c,
        &encsig_TX_c_self,
        &r_other.clone().into(),
        Y_other.clone(),
        old_commit_transaction,
    )?;

    Ok(TX_p)
}
