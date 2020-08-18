use crate::{keys::OwnershipKeyPair, transaction::PunishTransaction, ChannelState, RevokedState};
use bitcoin::Transaction;

pub struct Party0 {
    x_self: OwnershipKeyPair,
    revoked_states: Vec<RevokedState>,
}

#[derive(Debug, thiserror::Error)]
#[error("transaction cannot be punished")]
pub struct NotOldCommitTransaction;

impl Party0 {
    pub fn punish(&self, transaction: Transaction) -> anyhow::Result<PunishTransaction> {
        let RevokedState {
            channel_state:
                ChannelState {
                    TX_c,
                    Y_other,
                    encsig_TX_c_self,
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
            encsig_TX_c_self,
            r_other.into(),
            self.x_self.clone(),
        )?;

        Ok(TX_p)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        keys::{PublishingKeyPair, RevocationKeyPair},
        signature::decrypt,
        transaction::{CommitTransaction, FundingTransaction, SplitTransaction},
        ChannelBalance,
    };
    use bitcoin::{Amount, TxIn};

    #[test]
    fn punish_publication_of_revoked_commit_transaction() {
        let x_alice = OwnershipKeyPair::new_random();
        let x_bob = OwnershipKeyPair::new_random();

        let r_alice = RevocationKeyPair::new_random();
        let r_bob = RevocationKeyPair::new_random();

        let y_alice = PublishingKeyPair::new_random();
        let y_bob = PublishingKeyPair::new_random();

        let one_btc = Amount::from_btc(1.0).unwrap();

        let TX_f = FundingTransaction::new(
            (x_alice.public(), (TxIn::default(), one_btc)),
            (x_bob.public(), (TxIn::default(), one_btc)),
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

        let TX_s = SplitTransaction::new(
            &TX_c,
            ChannelBalance {
                a: (one_btc, x_alice.public()),
                b: (one_btc, x_bob.public()),
            },
        );

        let alice_encsig = TX_c.encsign_once(x_alice.clone(), y_bob.public());
        let bob_encsig = TX_c.encsign_once(x_bob.clone(), y_alice.public());

        let revoked_state = RevokedState {
            channel_state: ChannelState {
                TX_c: TX_c.clone(),
                encsig_TX_c_self: alice_encsig.clone(),
                encsig_TX_c_other: bob_encsig.clone(),
                r_self: r_alice,
                R_other: r_bob.public(),
                y_self: y_alice.clone(),
                Y_other: y_bob.public(),
                TX_s,
            },
            r_other: r_bob.into(),
        };

        let party0 = Party0 {
            x_self: x_alice.clone(),
            revoked_states: vec![revoked_state],
        };

        let published_revoked_TX_c = {
            let alice_sig = decrypt(y_bob.into(), alice_encsig);
            let bob_sig = decrypt(y_alice.into(), bob_encsig);

            TX_c.add_signatures((x_alice.public(), alice_sig), (x_bob.public(), bob_sig))
                .unwrap()
        };

        let _TX_p = party0.punish(published_revoked_TX_c).unwrap();
    }
}
