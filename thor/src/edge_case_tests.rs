use crate::{
    test_harness::{
        build_runtime, generate_balances, make_transports, make_wallets, swap_beta_ptlc_bob,
    },
    Channel, MedianTime, PtlcSecret,
};
use bitcoin::Amount;
use bitcoin_harness::Bitcoind;

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

    let hold_secret = true;
    let swap_beta_ptlc_alice = alice_channel.swap_beta_ptlc_alice(
        &mut alice_transport,
        &alice_wallet,
        ptlc_amount,
        secret,
        alpha_absolute_expiry,
        split_transaction_relative_expiry,
        ptlc_absolute_expiry,
        hold_secret,
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
            swap_beta_ptlc_alice,
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
