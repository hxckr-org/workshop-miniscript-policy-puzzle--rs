use std::collections::HashMap;

use miniscript::{
    bitcoin::{key::Secp256k1, Amount},
    descriptor::Wsh,
    Descriptor,
};
use workshop_miniscript_policy_puzzle__rs::{
    generate_new_checked_address, mine_bitcoins, setup_bitcoind, spending_tx, wallet_keypairs,
};

/// This test checks to see that a single key can spend when encumbered by the
/// spending condition requiring just the key. The tasks here require:
/// 1. The creation of an appropriate policy and compilation to miniscript.
/// 2. The provision of witness requirements to satisfy the spending condition.
#[test]
fn test_one_key_can_spend() {
    // 1. Setup bitcoind
    let bitcoind_inst = setup_bitcoind().expect("Failed to setup bitcoind");
    let secp = Secp256k1::new();

    let (private_key, public_key) = wallet_keypairs(&bitcoind_inst, &secp, 1)[0];

    // 2. Task 1: Create miniscript policy for the single-key spending condition.
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
    let coinbase_tx = mine_bitcoins(&bitcoind_inst, &output_descr, 1);

    // 5. Generate spending tx and valid signature.
    let dest_address = generate_new_checked_address(&bitcoind_inst);
    let amount = Amount::from_sat(coinbase_tx.output[0].value.to_sat() - 10_000);
    let mut spend_tx = spending_tx(dest_address.clone(), amount, &coinbase_tx);

    let bitcoin_script = miniscript.encode();
    let ws = bitcoin_script.as_script();

    // Task 3: Valid signature generation
    let signature =
        todo!("generate a signature matching the public key encoded in the spending condition");
    // HINT: Find generate_signature helper function.

    let mut satisfier: HashMap<
        miniscript::bitcoin::PublicKey,
        miniscript::bitcoin::ecdsa::Signature,
    > = HashMap::new();
    todo!("insert signature and corresponding public key into satisfier");

    assert!(output_descr
        .satisfy(&mut spend_tx.input[0], satisfier)
        .is_ok());
}
