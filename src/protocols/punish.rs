use crate::{
    keys::OwnershipKeyPair, transaction::PunishTransaction, Channel, ChannelState, RevokedState,
};
use bitcoin::Transaction;

#[derive(Debug)]
pub struct State0 {
    x_self: OwnershipKeyPair,
    revoked_states: Vec<RevokedState>,
}

impl From<Channel> for State0 {
    fn from(channel: Channel) -> Self {
        State0 {
            x_self: channel.x_self,
            revoked_states: channel.revoked_states,
        }
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("transaction cannot be punished")]
pub struct NotOldCommitTransaction;

impl State0 {
    pub fn new(x_self: OwnershipKeyPair, revoked_states: Vec<RevokedState>) -> Self {
        Self {
            x_self,
            revoked_states,
        }
    }

    pub fn punish(&self, transaction: Transaction) -> anyhow::Result<PunishTransaction> {
        let RevokedState {
            channel_state:
                ChannelState {
                    TX_c,
                    Y_other,
                    encsig_TX_c_self: our_encsig_TX_c,
                    ..
                },
            r_other,
        } = self
            .revoked_states
            .clone()
            .into_iter()
            .find(|state| state.channel_state.TX_c.txid() == transaction.txid())
            .ok_or_else(|| NotOldCommitTransaction)?;

        let TX_p = PunishTransaction::new(
            transaction,
            TX_c,
            Y_other,
            our_encsig_TX_c,
            r_other.into(),
            self.x_self.clone(),
        )?;

        Ok(TX_p)
    }
}
