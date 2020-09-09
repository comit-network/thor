use crate::{
    channel::ChannelState,
    keys::{
        OwnershipKeyPair, OwnershipPublicKey, PublishingKeyPair, PublishingPublicKey,
        RevocationKeyPair, RevocationPublicKey, RevocationSecretKey,
    },
    transaction::{balance, ptlc, CommitTransaction, FundingTransaction, SplitTransaction},
    Channel, Ptlc, RevokedState, SplitOutput, StandardChannelState,
};
use anyhow::Context;
use bitcoin::Address;
use ecdsa_fun::{adaptor::EncryptedSignature, Signature};

/// First message of the channel update protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ShareKeys {
    R: RevocationPublicKey,
    Y: PublishingPublicKey,
}

/// Second message of the channel update protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ShareSplitSignature {
    sig_TX_s: Signature,
}

/// Third message of the channel update protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct ShareCommitEncryptedSignature {
    encsig_TX_c: EncryptedSignature,
}

/// Fourth and last message of the channel update protocol.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct RevealRevocationSecretKey {
    r: RevocationSecretKey,
}

#[derive(Debug)]
pub(in crate::channel) struct State0 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f_body: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    new_split_outputs: Vec<SplitOutput>,
    time_lock: u32,
    r_self: RevocationKeyPair,
    y_self: PublishingKeyPair,
}

impl State0 {
    pub(in crate::channel) fn new(
        channel: Channel,
        new_split_outputs: Vec<SplitOutput>,
        time_lock: u32,
    ) -> Self {
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
            new_split_outputs,
            time_lock,
            r_self,
            y_self,
        }
    }

    pub(in crate::channel) fn compose(&self) -> ShareKeys {
        ShareKeys {
            R: self.r_self.public(),
            Y: self.y_self.public(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        ShareKeys {
            R: R_other,
            Y: Y_other,
        }: ShareKeys,
    ) -> anyhow::Result<State1Kind> {
        let TX_c = CommitTransaction::new(
            &self.TX_f_body,
            [
                (
                    self.x_self.public(),
                    self.r_self.public(),
                    self.y_self.public(),
                ),
                (self.X_other.clone(), R_other.clone(), Y_other.clone()),
            ],
            self.time_lock,
        )?;
        let encsig_TX_c_self = TX_c.encsign_once(&self.x_self, Y_other.clone());

        let TX_s = SplitTransaction::new(&TX_c, self.new_split_outputs.clone())?;
        let sig_TX_s_self = TX_s.sign_once(&self.x_self);

        let state = State1 {
            x_self: self.x_self.clone(),
            X_other: self.X_other,
            final_address_self: self.final_address_self,
            final_address_other: self.final_address_other,
            TX_f: self.TX_f_body,
            current_state: self.current_state,
            revoked_states: self.revoked_states,
            new_split_outputs: self.new_split_outputs.clone(),
            r_self: self.r_self,
            R_other,
            y_self: self.y_self,
            Y_other,
            TX_c,
            TX_s,
            encsig_TX_c_self,
            sig_TX_s_self,
        };

        // NOTE: We assume that there's only one PTLC output
        match self
            .new_split_outputs
            .into_iter()
            .find_map(|output| match output {
                SplitOutput::Ptlc(ptlc) => Some(ptlc),
                SplitOutput::Balance { .. } => None,
            }) {
            None => Ok(State1Kind::State1(state)),
            Some(ptlc) if ptlc.X_funder == self.x_self.public() => Ok(
                State1Kind::State1PtlcFunder(State1PtlcFunder::new(state, ptlc)?),
            ),
            Some(ptlc) if ptlc.X_redeemer == self.x_self.public() => Ok(
                State1Kind::State1PtlcRedeemer(State1PtlcRedeemer::new(state, ptlc)?),
            ),
            _ => anyhow::bail!("ownership of PTLC output is not shared by X_self"),
        }
    }
}

/// The three possible states in which a party can be in after receiving the
/// first message.
///
/// If a `PtlcOutput` is found among the new `SplitOutput`s for the update,
/// depending on whether the party is identified as the funder or the redeemer
/// of said output, the party will transition to `State1PtlcFunder` or
/// `State1PtlcRedeemer` respectively.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(in crate::channel) enum State1Kind {
    State1(State1),
    State1PtlcFunder(State1PtlcFunder),
    State1PtlcRedeemer(State1PtlcRedeemer),
}

/// Message sent by the PTLC funder in a channel update protocol execution
/// involving a PTLC output.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct SignaturesPtlcFunder {
    encsig_TX_ptlc_redeem_funder: EncryptedSignature,
    sig_TX_ptlc_refund_funder: Signature,
}

/// Message sent by the PTLC redeemer in a channel update protocol execution
/// involving a PTLC output.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug)]
pub struct SignaturesPtlcRedeemer {
    sig_TX_ptlc_redeem_redeemer: Signature,
    sig_TX_ptlc_refund_redeemer: Signature,
}

/// A party who has exchanged `RevocationPublicKey`s and `PublishingPublicKey`s
/// with the counterparty and is ready to start exchanging signatures for the
/// `ptlc::RedeemTransaction` and `ptlc::RefundTransaction` involving a PTLC
/// output which they are funding.
#[derive(Debug)]
pub(in crate::channel) struct State1PtlcFunder {
    inner: State1,
    ptlc: Ptlc,
    TX_ptlc_redeem: ptlc::RedeemTransaction,
    TX_ptlc_refund: ptlc::RefundTransaction,
    encsig_TX_ptlc_redeem_funder: EncryptedSignature,
    sig_TX_ptlc_refund_funder: Signature,
}

impl State1PtlcFunder {
    pub(in crate::channel) fn new(state: State1, ptlc: Ptlc) -> anyhow::Result<Self> {
        let TX_ptlc_redeem = ptlc::RedeemTransaction::new(
            &state.TX_s,
            ptlc.clone(),
            state.final_address_other.clone(),
        )?;
        let encsig_TX_ptlc_redeem_funder = TX_ptlc_redeem.encsign_once(&state.x_self, ptlc.point());

        let TX_ptlc_refund = ptlc::RefundTransaction::new(
            &state.TX_s,
            ptlc.clone(),
            state.final_address_self.clone(),
        )?;
        let sig_TX_ptlc_refund_funder = TX_ptlc_refund.sign_once(&state.x_self);

        Ok(Self {
            inner: state,
            ptlc,
            TX_ptlc_redeem,
            TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_refund_funder,
        })
    }

    pub(in crate::channel) fn compose(&self) -> SignaturesPtlcFunder {
        SignaturesPtlcFunder {
            encsig_TX_ptlc_redeem_funder: self.encsig_TX_ptlc_redeem_funder.clone(),
            sig_TX_ptlc_refund_funder: self.sig_TX_ptlc_refund_funder.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        message: SignaturesPtlcRedeemer,
    ) -> anyhow::Result<WithPtlc<State1>> {
        self.TX_ptlc_refund
            .verify_sig(
                self.inner.X_other.clone(),
                &message.sig_TX_ptlc_refund_redeemer,
            )
            .context("failed to verify sig_TX_ptlc_refund sent by PTLC redeemer")?;

        let mut TX_ptlc_refund = self.TX_ptlc_refund;
        TX_ptlc_refund.add_signatures(
            (
                self.inner.x_self.public(),
                self.sig_TX_ptlc_refund_funder.clone(),
            ),
            (
                self.inner.X_other.clone(),
                message.sig_TX_ptlc_refund_redeemer.clone(),
            ),
        )?;

        Ok(WithPtlc {
            state: self.inner,
            ptlc: self.ptlc,
            TX_ptlc_redeem: self.TX_ptlc_redeem,
            TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder: self.encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_redeem_redeemer: message.sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_funder: self.sig_TX_ptlc_refund_funder,
            sig_TX_ptlc_refund_redeemer: message.sig_TX_ptlc_refund_redeemer,
        })
    }
}

/// A party who has exchanged `RevocationPublicKey`s and `PublishingPublicKey`s
/// with the counterparty and is ready to start exchanging signatures for the
/// `ptlc::RedeemTransaction` and `ptlc::RefundTransaction` involving a PTLC
/// output which they are redeeming.
#[derive(Debug)]
pub(in crate::channel) struct State1PtlcRedeemer {
    inner: State1,
    ptlc: Ptlc,
    TX_ptlc_redeem: ptlc::RedeemTransaction,
    TX_ptlc_refund: ptlc::RefundTransaction,
    sig_TX_ptlc_redeem_redeemer: Signature,
    sig_TX_ptlc_refund_redeemer: Signature,
}

impl State1PtlcRedeemer {
    pub(in crate::channel) fn new(state: State1, ptlc: Ptlc) -> anyhow::Result<Self> {
        let TX_ptlc_redeem = ptlc::RedeemTransaction::new(
            &state.TX_s,
            ptlc.clone(),
            state.final_address_self.clone(),
        )?;
        let sig_TX_ptlc_redeem_redeemer = TX_ptlc_redeem.sign_once(&state.x_self);

        let TX_ptlc_refund = ptlc::RefundTransaction::new(
            &state.TX_s,
            ptlc.clone(),
            state.final_address_other.clone(),
        )?;
        let sig_TX_ptlc_refund_redeemer = TX_ptlc_refund.sign_once(&state.x_self);

        Ok(Self {
            inner: state,
            ptlc,
            TX_ptlc_redeem,
            TX_ptlc_refund,
            sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_redeemer,
        })
    }

    pub(in crate::channel) fn compose(&self) -> SignaturesPtlcRedeemer {
        SignaturesPtlcRedeemer {
            sig_TX_ptlc_redeem_redeemer: self.sig_TX_ptlc_redeem_redeemer.clone(),
            sig_TX_ptlc_refund_redeemer: self.sig_TX_ptlc_refund_redeemer.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        message: SignaturesPtlcFunder,
    ) -> anyhow::Result<WithPtlc<State1>> {
        self.TX_ptlc_redeem
            .verify_encsig(
                self.inner.X_other.clone(),
                self.ptlc.point().into(),
                &message.encsig_TX_ptlc_redeem_funder,
            )
            .context("failed to verify encsig_TX_ptlc_redeem sent by PTLC funder")?;

        Ok(WithPtlc {
            state: self.inner,
            ptlc: self.ptlc,
            TX_ptlc_redeem: self.TX_ptlc_redeem,
            TX_ptlc_refund: self.TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder: message.encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_redeem_redeemer: self.sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_funder: message.sig_TX_ptlc_refund_funder,
            sig_TX_ptlc_refund_redeemer: self.sig_TX_ptlc_refund_redeemer,
        })
    }
}

/// A party who has exchanged `RevocationPublicKey`s and `PublishingPublicKey`s
/// with the counterparty and is ready to start exchanging signatures.
#[derive(Clone, Debug)]
pub(in crate::channel) struct State1 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    new_split_outputs: Vec<SplitOutput>,
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
    pub(in crate::channel) fn compose(&self) -> ShareSplitSignature {
        ShareSplitSignature {
            sig_TX_s: self.sig_TX_s_self.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        mut self,
        ShareSplitSignature {
            sig_TX_s: sig_TX_s_other,
        }: ShareSplitSignature,
    ) -> anyhow::Result<State2> {
        self.TX_s
            .verify_sig(self.X_other.clone(), &sig_TX_s_other)
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
            new_split_outputs: self.new_split_outputs,
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
#[derive(Debug)]
pub(in crate::channel) struct State2 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    new_split_outputs: Vec<SplitOutput>,
    r_self: RevocationKeyPair,
    R_other: RevocationPublicKey,
    y_self: PublishingKeyPair,
    Y_other: PublishingPublicKey,
    TX_c: CommitTransaction,
    signed_TX_s: SplitTransaction,
    encsig_TX_c_self: EncryptedSignature,
}

impl State2 {
    pub(in crate::channel) fn compose(&self) -> ShareCommitEncryptedSignature {
        ShareCommitEncryptedSignature {
            encsig_TX_c: self.encsig_TX_c_self.clone(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        ShareCommitEncryptedSignature {
            encsig_TX_c: encsig_TX_c_other,
        }: ShareCommitEncryptedSignature,
    ) -> anyhow::Result<State3> {
        self.TX_c
            .verify_encsig(
                self.X_other.clone(),
                self.y_self.public(),
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
            new_split_outputs: self.new_split_outputs,
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
#[derive(Debug)]
pub(in crate::channel) struct State3 {
    x_self: OwnershipKeyPair,
    X_other: OwnershipPublicKey,
    final_address_self: Address,
    final_address_other: Address,
    TX_f: FundingTransaction,
    current_state: ChannelState,
    revoked_states: Vec<RevokedState>,
    new_split_outputs: Vec<SplitOutput>,
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
    pub(in crate::channel) fn compose(&self) -> RevealRevocationSecretKey {
        RevealRevocationSecretKey {
            r: StandardChannelState::from(self.current_state.clone())
                .r_self
                .into(),
        }
    }

    pub(in crate::channel) fn interpret(
        self,
        RevealRevocationSecretKey { r: r_other }: RevealRevocationSecretKey,
    ) -> anyhow::Result<Channel> {
        StandardChannelState::from(self.current_state.clone())
            .R_other
            .verify_revocation_secret_key(&r_other)?;

        let revoked_state = RevokedState {
            channel_state: self.current_state,
            r_other,
        };
        let mut revoked_states = self.revoked_states;
        revoked_states.push(revoked_state);

        let current_state = ChannelState::Standard(StandardChannelState {
            balance: balance(
                self.new_split_outputs,
                &self.final_address_self,
                &self.final_address_other,
            ),
            TX_c: self.TX_c,
            encsig_TX_c_other: self.encsig_TX_c_other,
            r_self: self.r_self,
            R_other: self.R_other,
            y_self: self.y_self,
            Y_other: self.Y_other,
            signed_TX_s: self.signed_TX_s,
        });

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

#[derive(Debug, Clone)]
pub(in crate::channel) struct WithPtlc<S> {
    state: S,
    ptlc: Ptlc,
    TX_ptlc_redeem: ptlc::RedeemTransaction,
    TX_ptlc_refund: ptlc::RefundTransaction,
    encsig_TX_ptlc_redeem_funder: EncryptedSignature,
    sig_TX_ptlc_redeem_redeemer: Signature,
    sig_TX_ptlc_refund_funder: Signature,
    sig_TX_ptlc_refund_redeemer: Signature,
}

impl WithPtlc<State1> {
    pub(in crate::channel) fn compose(&self) -> ShareSplitSignature {
        self.state.compose()
    }

    pub(in crate::channel) fn interpret(
        self,
        message: ShareSplitSignature,
    ) -> anyhow::Result<WithPtlc<State2>> {
        let state = self.state.interpret(message)?;

        Ok(WithPtlc {
            state,
            ptlc: self.ptlc,
            TX_ptlc_redeem: self.TX_ptlc_redeem,
            TX_ptlc_refund: self.TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder: self.encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_redeem_redeemer: self.sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_funder: self.sig_TX_ptlc_refund_funder,
            sig_TX_ptlc_refund_redeemer: self.sig_TX_ptlc_refund_redeemer,
        })
    }
}

impl WithPtlc<State2> {
    pub(in crate::channel) fn compose(&self) -> ShareCommitEncryptedSignature {
        self.state.compose()
    }

    pub(in crate::channel) fn interpret(
        self,
        message: ShareCommitEncryptedSignature,
    ) -> anyhow::Result<WithPtlc<State3>> {
        let state = self.state.interpret(message)?;

        Ok(WithPtlc {
            state,
            ptlc: self.ptlc,
            TX_ptlc_redeem: self.TX_ptlc_redeem,
            TX_ptlc_refund: self.TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder: self.encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_redeem_redeemer: self.sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_funder: self.sig_TX_ptlc_refund_funder,
            sig_TX_ptlc_refund_redeemer: self.sig_TX_ptlc_refund_redeemer,
        })
    }
}

impl WithPtlc<State3> {
    pub(in crate::channel) fn compose(&self) -> RevealRevocationSecretKey {
        self.state.compose()
    }

    pub(in crate::channel) fn interpret(
        self,
        message: RevealRevocationSecretKey,
    ) -> anyhow::Result<Channel> {
        let mut channel = self.state.interpret(message)?;

        let current_state = ChannelState::WithPtlc {
            inner: channel.current_state.into(),
            ptlc: self.ptlc,
            TX_ptlc_redeem: self.TX_ptlc_redeem,
            TX_ptlc_refund: self.TX_ptlc_refund,
            encsig_TX_ptlc_redeem_funder: self.encsig_TX_ptlc_redeem_funder,
            sig_TX_ptlc_redeem_redeemer: self.sig_TX_ptlc_redeem_redeemer,
            sig_TX_ptlc_refund_funder: self.sig_TX_ptlc_refund_funder,
            sig_TX_ptlc_refund_redeemer: self.sig_TX_ptlc_refund_redeemer,
        };

        channel.current_state = current_state;

        Ok(channel)
    }
}
