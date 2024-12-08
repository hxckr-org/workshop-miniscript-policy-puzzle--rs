use std::collections::HashMap;

// use hex::ToHex;
use miniscript::{
    bitcoin::{key::Secp256k1, Amount},
    descriptor::Wsh,
    Descriptor,
};
use workshop_miniscript_policy_puzzle__rs::{
    generate_new_checked_address, mine_bitcoins, setup_bitcoind, spending_tx, wallet_keypairs,
};

/// This test checks to see that a one of two keys (one likelier than the other) can
/// spend when encumbered by the spending condition requiring any one of the keys.
/// The tasks here require:
/// 1. The creation of an appropriate policy and compilation to miniscript.
/// 2. The provision of witness requirements to satisfy the spending condition.
#[test]
fn one_of_two_one_unlikely() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();
    let wallet_keypair = wallet_keypairs(&bitcoind_inst, &secp, 2);
    let (private_key_1, public_key_1) = wallet_keypair[0];
    let (_private_key_2, public_key_2) = wallet_keypair[1];

    // 2. Task 1: Create miniscript policy for the spending condition.
    let policy_str = todo!("write the policy that matches the spending condition.");
    let policy = todo!("create a concrete policy from policy_str");

    // 3. Task 2: Compile policy to miniscript.
    let miniscript = todo!("compile the policy to miniscript with a Segwitv0 script context");
    // HINT: You can choose "any" script context you prefer, however, take note to modify how the
    // output descriptor is created to take into account your preferred script context.

    // 4. Mine bitcoins to descriptor address generated from miniscript.
    let output_descr = Descriptor::Wsh(
        Wsh::new(miniscript.clone()).expect("Failed to create descriptor from miniscript"),
    );
    let coinbase_tx = mine_bitcoins(&bitcoind_inst, &output_descr, 1, 0);

    // 5. Generate spending tx and valid signature.
    let dest_address = generate_new_checked_address(&bitcoind_inst);
    let amount = Amount::from_sat(coinbase_tx.output[0].value.to_sat() * 4 / 5);
    let mut spend_tx = spending_tx(dest_address.clone(), amount, &coinbase_tx);

    let bitcoin_script = miniscript.encode();
    let ws = bitcoin_script.as_script();

    // Task 3: Valid signature(s) generation
    let signature_1 = todo!(
        "generate a signature matching the unlikely public key encoded in the spending condition"
    );

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();

    // Task 4: Check if the unlikely key alone can spend.
    todo!("insert signature and corresponding to unlikely public key into satisfier");

    assert!(output_descr
        .satisfy(&mut spend_tx.input[0], satisfier)
        .is_ok());

    let mut witness = vec![];
    for witness_item in spend_tx.input[0].witness.iter() {
        let hex: String = witness_item.iter().map(|b| format!("{:02x}", b)).collect();
        witness.push(hex);
    }

    assert!(witness.len() == 4);
    assert_eq!(witness[0], signature_1.to_string());
    assert_eq!(witness[1], public_key_1.inner.to_string());
    assert_eq!(witness[2], "".to_string());
}

#[test]
fn one_of_two_one_more_likely() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();
    let wallet_keypair = wallet_keypairs(&bitcoind_inst, &secp, 2);
    let (_private_key_1, public_key_1) = wallet_keypair[0];
    let (private_key_2, public_key_2) = wallet_keypair[1];

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
    let mut spend_tx = spending_tx(dest_address.clone(), amount, &coinbase_tx);

    let bitcoin_script = miniscript.encode();
    let ws = bitcoin_script.as_script();

    // Task 3: Valid signature(s) generation
    let signature_2 = todo!(
        "generate a signature matching the more likely public key encoded in the spending condition"
    );

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();
    todo!("insert signature and corresponding public key into satisfier");

    assert!(output_descr
        .satisfy(&mut spend_tx.input[0], satisfier)
        .is_ok());

    let mut witness = vec![];
    for witness_item in spend_tx.input[0].witness.iter() {
        let hex: String = witness_item.iter().map(|b| format!("{:02x}", b)).collect();
        witness.push(hex);
    }

    assert!(witness.len() == 2);
    assert_eq!(witness[0], signature_2.to_string());

    // Additional (optional) task
    // Task 6: Check that the likely key alone can spend if both keys are available.
}
