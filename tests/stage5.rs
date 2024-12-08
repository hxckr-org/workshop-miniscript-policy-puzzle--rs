use std::{collections::HashMap, str::FromStr};

use bitcoind::bitcoincore_rpc::{json::ListTransactionResult, RpcApi};
use miniscript::{
    bitcoin::{ecdsa::Signature, key::Secp256k1, Amount, EcdsaSighashType, PublicKey},
    descriptor::Wsh,
    policy::Concrete,
    Descriptor,
};
use workshop_miniscript_policy_puzzle__rs::{
    generate_new_checked_address, generate_signature, lock_tx, mine_bitcoins,
    mine_bitcoins_to_address, setup_bitcoind, spending_tx, wallet_keypairs,
};

/// Single signing key test.
///
/// This test ensures that a single signing key (user's) is insufficient to
/// spend when encumbered by a spending condition. The condition requires:
/// - The user's key *and*
/// - Either the service provider's key or a timelock (if the timelock has been
///   reached or exceeded).
///
/// Tasks:
/// 1. Create an appropriate policy and compile it into a Miniscript.
/// 2. Provide the necessary witness requirements to satisfy the spending
///    condition.
#[test]
fn user_without_service_or_timelock() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();
    let wallet_keypair = wallet_keypairs(&bitcoind_inst, &secp, 2);
    let (user_private_key, user_public_key) = wallet_keypair[0];
    let (_service_private_key, service_public_key) = wallet_keypair[1];

    // 2. Task 1: Create miniscript policy for the spending condition.
    let policy_str = todo!("write the policy that matches the spending condition.");
    let policy = todo!("create a concrete policy from policy_str");

    // 3. Task 2: Compile policy to miniscript.
    let miniscript = todo!("compile the policy to miniscript with a Segwitv0 script context");

    // 4. Mine bitcoins to descriptor address generated from miniscript.
    let output_descr = Descriptor::Wsh(
        Wsh::new(miniscript.clone()).expect("Failed to create descriptor from miniscript"),
    );

    let coinbase_tx = mine_bitcoins(&bitcoind_inst, &output_descr, 1, 0);

    // 5. Generate spending tx and valid signature.
    let dest_address = generate_new_checked_address(&bitcoind_inst);
    let amount = Amount::from_sat(coinbase_tx.output[0].value.to_sat() * 4 / 5);
    let mut spend_tx = spending_tx(dest_address.clone(), amount, &coinbase_tx, rel_timelock);

    let bs = miniscript.encode();
    let ws = bs.as_script();

    // Task 3: Valid signature(s) generation
    let signature_user =
        todo!("generate a signature matching the public key encoded in the spending condition");

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();

    // Check if user's key alone can spend
    todo!("insert signature and corresponding public key into satisfier");

    assert!(
        output_descr
            .satisfy(&mut spend_tx.input[0], &satisfier)
            .is_err(),
        "user's key alone is insufficient in producing a satisfying witness."
    );
}

/// Double signing keys test.
///
/// This test ensures that a user's key and a service provider's key are
/// sufficient to spend when encumbered by a spending condition. The condition requires:
/// - The user's key *and*
/// - Either the service provider's key or a timelock (if the timelock has been
///   reached or exceeded).
///
/// Tasks:
/// 1. Create an appropriate policy and compile it into a Miniscript.
/// 2. Provide the necessary witness requirements to satisfy the spending
///    condition.
#[test]
fn user_and_service() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();
    let wallet_keypair = wallet_keypairs(&bitcoind_inst, &secp, 2);
    let (user_private_key, user_public_key) = wallet_keypair[0];
    let (service_private_key, service_public_key) = wallet_keypair[1];

    // 2. Task 1: Create miniscript policy for the spending condition.
    let policy_str = todo!("write the policy that matches the spending condition.");
    let policy = todo!("create a concrete policy from policy_str");

    // 3. Task 2: Compile policy to miniscript.
    let miniscript = todo!("compile the policy to miniscript with a Segwitv0 script context");

    // 4. Mine bitcoins to descriptor address generated from miniscript.
    let output_descr = Descriptor::Wsh(
        Wsh::new(miniscript.clone()).expect("Failed to create descriptor from miniscript"),
    );
    let coinbase_tx = mine_bitcoins(&bitcoind_inst, &output_descr, 1, 0);

    // 5. Generate spending tx and valid signature.
    let dest_address = generate_new_checked_address(&bitcoind_inst);
    let amount = Amount::from_sat(coinbase_tx.output[0].value.to_sat() * 4 / 5);
    let mut spend_tx = spending_tx(dest_address.clone(), amount, &coinbase_tx, rel_timelock);

    let bs = miniscript.encode();
    let ws = bs.as_script();

    // Task 3: Valid signature(s) generation
    let signature_user = todo!(
        "generate a user signature matching the public key encoded in the spending condition"
    );
    let signature_service = todo!(
        "generate a service signature matching the public key encoded in the spending condition"
    );

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();

    // Check if both keys alone can spend
    todo!("insert signature and corresponding public key into satisfier");

    assert!(
        output_descr
            .satisfy(&mut spend_tx.input[0], &satisfier)
            .is_ok(),
        "Possible invalid user &/or service keys. They should produce a satisfying witness."
    );
}

/// Single signing key & elapsed timelock test.
///
/// This test ensures that a user's key and an elapsed timelock are
/// sufficient to spend when encumbered by a spending condition. The condition requires:
/// - The user's key *and*
/// - Either the service provider's key or a timelock (if the timelock has been
///   reached or exceeded).
///
/// Tasks:
/// 1. Create an appropriate policy and compile it into a Miniscript.
/// 2. Provide the necessary witness requirements to satisfy the spending
///    condition.
#[test]
fn user_and_timelock() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();
    let wallet_keypair = wallet_keypairs(&bitcoind_inst, &secp, 2);
    let (user_private_key, user_public_key) = wallet_keypair[0];
    let (_service_private_key, service_public_key) = wallet_keypair[1];

    // 2. Task 1: Create miniscript policy for the spending condition.
    let policy_str = todo!("write the policy that matches the spending condition.");
    let policy = todo!("create a concrete policy from policy_str");

    // 3. Task 2: Compile policy to miniscript.
    let miniscript = todo!("compile the policy to miniscript with a Segwitv0 script context");

    // 4. Generate lock_tx sending bitcoins to a miniscript descriptor address.
    let output_descr = Descriptor::Wsh(
        Wsh::new(miniscript.clone()).expect("Failed to create descriptor from miniscript"),
    );
    let output_descr_address = output_descr
        .address(miniscript::bitcoin::Network::Regtest)
        .expect("Failed to compute bitcoin address from descriptor");
    let lock_tx = lock_tx(&bitcoind_inst, output_descr_address.to_string());

    // Broadcast lock_tx and mine up to OP_CSV blocks to confirm.
    let broadcast_lock_tx = bitcoind_inst.client.send_raw_transaction(&lock_tx);
    let rand_address = generate_new_checked_address(&bitcoind_inst);
    let _ = mine_bitcoins_to_address(&bitcoind_inst, &rand_address, 6, 0);
    match broadcast_lock_tx {
        Ok(txid) => {
            let txs = bitcoind_inst
                .client
                .list_transactions(None, None, None, None)
                .expect("Failed to list transactions");

            let res: Vec<&ListTransactionResult> =
                txs.iter().filter(|tx| tx.info.txid == txid).collect();

            assert_eq!(res[0].info.confirmations, 6);
            assert!(res.len() == 1);
        }
        Err(e) => println!("broadcast error: {e}"),
    }

    // 5. Generate spending tx and valid signature.
    let dest_address = generate_new_checked_address(&bitcoind_inst);
    let amount = Amount::from_sat(lock_tx.output[0].value.to_sat() - 10_000);

    let mut spend_tx = spending_tx(dest_address.clone(), amount, &lock_tx, rel_timelock);

    let bs = miniscript.encode();
    let ws = bs.as_script();

    // Task 3: Valid signature(s) generation
    let signature_user = todo!(
        "generate a signature matching the user's public key encoded in the spending condition"
    );

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();

    // Check if user's valid key and the elapsed timelock can spend
    let invalid_signature_service =
        todo!("generate an invalid or null service signature matching the public key encoded in the spending condition");

    todo!("insert signature and corresponding public key into satisfier");

    assert!(output_descr
        .satisfy(&mut spend_tx.input[0], &satisfier)
        .is_ok());
}
