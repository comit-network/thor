use crate::{
    test_harness::{
        build_runtime, generate_balances, make_transports, make_wallets, swap_beta_ptlc_bob,
    },
    Balance, Channel, MedianTime, PtlcSecret,
};
use bitcoin::Amount;
use bitcoin_harness::Bitcoind;

#[test]
fn punish_publication_of_revoked_commit_transaction() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // Parties agree on a new channel balance: Alice pays 0.5 a Bitcoin to Bob
    let payment = Amount::from_btc(0.5).unwrap();
    let alice_balance = fund_amount_alice - payment;
    let bob_balance = fund_amount_bob + payment;

    let alice_update = alice_channel.update_balance(
        &mut alice_transport,
        Balance {
            ours: alice_balance,
            theirs: bob_balance,
        },
        time_lock,
    );
    let bob_update = bob_channel.update_balance(
        &mut bob_transport,
        Balance {
            ours: bob_balance,
            theirs: alice_balance,
        },
        time_lock,
    );

    runtime
        .block_on(futures::future::try_join(alice_update, bob_update))
        .unwrap();

    // Alice attempts to cheat by publishing a revoked commit transaction

    let signed_revoked_TX_c = alice_channel.latest_revoked_signed_TX_c().unwrap().unwrap();
    runtime
        .block_on(
            alice_wallet
                .0
                .send_raw_transaction(signed_revoked_TX_c.clone()),
        )
        .unwrap();

    // Bob sees the transaction and punishes Alice

    runtime
        .block_on(bob_channel.punish(&bob_wallet, signed_revoked_TX_c))
        .unwrap();

    let after_punish_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_punish_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    assert_eq!(
        after_punish_balance_alice, after_open_balance_alice,
        "Alice should get no money back after being punished"
    );
    assert_eq!(
        after_punish_balance_bob,
        after_open_balance_bob + fund_amount_bob * 2 - Amount::from_sat(crate::TX_FEE) * 2,
        "Bob should get all the money back after punishing Alice"
    );
}

#[test]
fn bob_can_refund_ptlc_if_alice_holds_onto_secret_after_first_update() {
    let mut runtime = build_runtime();

    let tc_client = testcontainers::clients::Cli::default();
    let bitcoind = Bitcoind::new(&tc_client, "0.19.1").unwrap();
    runtime.block_on(bitcoind.init(5)).unwrap();

    let fund_amount_alice = Amount::ONE_BTC;
    let fund_amount_bob = Amount::ONE_BTC;
    let (balance_alice, balance_bob) = generate_balances(fund_amount_alice, fund_amount_bob);

    let time_lock = 1;

    let (alice_wallet, bob_wallet) = runtime
        .block_on(make_wallets(&bitcoind, fund_amount_alice, fund_amount_bob))
        .unwrap();
    let (mut alice_transport, mut bob_transport) = make_transports();

    let alice_create = Channel::create(
        &mut alice_transport,
        &alice_wallet,
        balance_alice,
        time_lock,
    );
    let bob_create = Channel::create(&mut bob_transport, &bob_wallet, balance_bob, time_lock);

    let (mut alice_channel, mut bob_channel) = runtime
        .block_on(futures::future::try_join(alice_create, bob_create))
        .unwrap();

    let after_open_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_open_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    let secret = PtlcSecret::new_random();
    let point = secret.point();
    let ptlc_amount = Amount::from_btc(0.5).unwrap();

    let (alpha_absolute_expiry, ptlc_absolute_expiry, split_transaction_relative_expiry) = {
        let now = runtime.block_on(alice_wallet.median_time()).unwrap();

        let five_seconds = 5;
        let ptlc_absolute = now + five_seconds;
        let alpha_absolute = ptlc_absolute + five_seconds;

        let split_transaction_relative = 1;

        (alpha_absolute, ptlc_absolute, split_transaction_relative)
    };

    // Alice collaborates to add the PTLC to the channel, but does not reveal the
    // secret
    let add_ptlc_alice = alice_channel.add_ptlc_redeemer(
        &mut alice_transport,
        ptlc_amount,
        secret,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
    );

    let skip_final_update = false;
    let swap_beta_ptlc_bob = swap_beta_ptlc_bob(
        &mut bob_channel,
        &mut bob_transport,
        &bob_wallet,
        ptlc_amount,
        point,
        alpha_absolute_expiry,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
        skip_final_update,
    );

    runtime
        .block_on(futures::future::try_join(
            add_ptlc_alice,
            swap_beta_ptlc_bob,
        ))
        .unwrap();

    let after_close_balance_alice = runtime.block_on(alice_wallet.0.balance()).unwrap();
    let after_close_balance_bob = runtime.block_on(bob_wallet.0.balance()).unwrap();

    // A `SplitTransaction` containing a PTLC output has 2 balance outputs and 1
    // PTLC output, for a total of 3
    let n_outputs_split_transaction = 3;

    // The fees are distributed evenly between the outputs.
    let fee_deduction_per_split_output =
        Amount::from_sat(crate::TX_FEE + crate::TX_FEE) / n_outputs_split_transaction;

    // Alice will just claim her balance output
    let split_transaction_fee_alice = fee_deduction_per_split_output;

    // Bob will claim his balance output and refund the PTLC output
    let split_transaction_fee_bob = fee_deduction_per_split_output * 2;

    // Additionally, Bob pays an extra `thor::TX_FEE` to be able to refund the
    // PTLC output.
    let fee_deduction_for_ptlc_refund = Amount::from_sat(crate::TX_FEE);

    assert_eq!(
        after_close_balance_alice,
        after_open_balance_alice + fund_amount_alice - split_transaction_fee_alice,
        "Balance after closing channel should equal balance after opening plus PTLC amount,
         minus transaction fees"
    );

    assert_eq!(
        after_close_balance_bob,
        after_open_balance_bob + fund_amount_bob
            - split_transaction_fee_bob
            - fee_deduction_for_ptlc_refund,
        "Balance after closing channel and refunding PTLC should equal balance after opening
         plus PTLC amount, minus transaction fees"
    );
}
