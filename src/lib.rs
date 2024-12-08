use std::{collections::HashMap, str::FromStr};

use bitcoind::{
    anyhow::{self},
    bitcoincore_rpc::{
        self,
        json::{CreateRawTransactionInput, SigHashType},
        jsonrpc::{self, Response},
        Client, RpcApi,
    },
    BitcoinD, Conf,
};
use miniscript::{
    bitcoin::{
        absolute::LockTime,
        address::ParseError,
        bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
        ecdsa::Signature,
        key::Secp256k1,
        secp256k1::{All, Message},
        sighash::SighashCache,
        transaction::Version,
        Address, Amount, EcdsaSighashType, OutPoint, PrivateKey, PublicKey, Script, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Witness,
    },
    Descriptor,
};
use serde::Deserialize;
use serde_json::{from_str, value::RawValue};

#[derive(Debug, thiserror::Error)]
pub enum BitcoindError {
    #[error("BitcoindInitializationError: {0:#?}")]
    BitcoindInitializationError(anyhow::Error),
    #[error("WalletCreationError: {0:#?}")]
    WalletCreationError(anyhow::Error),
    #[error("JsonRpcError: {0:#?}")]
    CoreRpcError(bitcoincore_rpc::Error),
    #[error("AddressError: {0:#?}")]
    AddressError(ParseError),
    #[error("ParseJsonResponseError: {0:#?}")]
    ParseJsonResponseError(String),
    #[error("SerdeJson: {0:#?}")]
    SerdeJson(serde_json::Error),
}

/// Setup bitcoind with the default wallet. Returns the wallet-loaded daemon.
pub fn setup_bitcoind() -> Result<BitcoinD, BitcoindError> {
    let mut conf = Conf::default();
    conf.args.push("-txindex");

    let bitcoind = BitcoinD::from_downloaded_with_conf(&conf)
        .map_err(|e| BitcoindError::BitcoindInitializationError(e))?;

    Ok(bitcoind)
}

/// Return wallet descriptors of the default wallet provided the private key flag.
/// If set to true, lists the private descriptors.
pub fn get_wallet_descriptors(
    bitcoind_client: &Client,
    private: bool,
) -> Result<ListDescriptorsResponse, BitcoindError> {
    // 1. Get JSON RPC client.
    let jsonrpc_client = bitcoind_client.get_jsonrpc_client();

    // 2. Send `listdescriptors` request.
    let params = RawValue::from_string(format!(r#"{{"private": {}}}"#, private))
        .map_err(|e| BitcoindError::SerdeJson(e))?;
    let list_descriptors_req = jsonrpc_client.build_request("listdescriptors", Some(&params));
    let descriptors_resp = jsonrpc_client
        .send_request(list_descriptors_req)
        .map_err(|e| BitcoindError::CoreRpcError(bitcoind::bitcoincore_rpc::Error::JsonRpc(e)))?;

    // 3. Parse response.
    if let Some(error) = descriptors_resp.error {
        return Err(BitcoindError::CoreRpcError(
            bitcoincore_rpc::Error::JsonRpc(jsonrpc::Error::Rpc(error)),
        ));
    }
    let descriptors = parse_list_descriptors(descriptors_resp)?;

    // 4. Return list of descriptors
    Ok(descriptors)
}

#[derive(Debug, Deserialize)]
pub struct ListDescriptorsResponse {
    pub wallet_name: String,
    pub descriptors: Vec<DescriptorInfo>,
}

#[derive(Debug, Deserialize)]
pub struct DescriptorInfo {
    pub desc: String,
    pub timestamp: u64,
    pub active: bool,
    pub internal: bool,
    pub range: Option<(u64, u64)>,
    pub next: Option<u64>,
    pub next_index: Option<u64>,
}

/// Parse the list of wallet descriptors.
fn parse_list_descriptors(response: Response) -> Result<ListDescriptorsResponse, BitcoindError> {
    // Check if `result` exists
    let raw_result = response
        .result
        .ok_or(BitcoindError::ParseJsonResponseError(
            "No result field in the response".to_string(),
        ))?;

    // Deserialize the `result` into our `ListDescriptorsResponse` struct
    let parsed: ListDescriptorsResponse = from_str(raw_result.get()).map_err(|e| {
        BitcoindError::ParseJsonResponseError(format!("Failed to parse result: {}", e))
    })?;

    Ok(parsed)
}

/// Extract extended private keys from descriptor string.
pub fn extract_xprv_from_descriptor(descriptor: &str) -> Result<String, String> {
    // Find the starting index of "tprv" (or xprv in other cases)
    if let Some(start) = descriptor.find("tprv") {
        // Extract the substring starting from "tprv"
        let xprv_with_path = &descriptor[start..];
        // Split and isolate the xprv part before any path or metadata
        let xprv = xprv_with_path
            .split(&['/', ')', '#'][..]) // Stops at '/', ')' or '#'
            .next()
            .ok_or("Failed to parse xprv")?;
        // the xprv
        Ok(xprv.to_string())
    } else {
        Err("No xprv found in descriptor".to_string())
    }
}

/// Generate n key pairs from the loaded default wallet.
pub fn wallet_keypairs(
    bitcoind: &BitcoinD,
    secp: &Secp256k1<All>,
    n: usize,
) -> Vec<(PrivateKey, PublicKey)> {
    // 1. Retrieve wallet private descriptors
    let wallet_private_descriptors = get_wallet_descriptors(&bitcoind.client, true)
        .expect("Failed to retrieve wallet descriptors");

    // 2. Extract xprv from the first descriptor
    let xprv_str = extract_xprv_from_descriptor(&wallet_private_descriptors.descriptors[0].desc)
        .expect("Failed to extract xprv from descriptor");
    let wallet_xprv = Xpriv::from_str(&xprv_str).expect("Failed to parse xprv from str");

    // Generate n key pairs
    let mut key_pairs = Vec::with_capacity(n);

    for i in 0..n {
        // Derive a child private key using the derivation path
        let child_derivation_path = DerivationPath::from(vec![
            ChildNumber::Hardened { index: 84 },     // purpose
            ChildNumber::Hardened { index: 1 },      // coin type (testnet)
            ChildNumber::Hardened { index: 0 },      // account
            ChildNumber::Normal { index: 0 },        // change
            ChildNumber::Normal { index: i as u32 }, // address index
        ]);

        // Derive the child private key
        let derived_xprv = wallet_xprv
            .derive_priv(&secp, &child_derivation_path)
            .expect("Failed to derive child private key");

        // Create private key
        let private_key = PrivateKey {
            compressed: true,
            network: miniscript::bitcoin::NetworkKind::Test,
            inner: derived_xprv.private_key,
        };

        // Derive corresponding public key
        let derived_pubkey = PublicKey::from_private_key(&secp, &private_key);

        // Verify the derivation
        let xpub = Xpub::from_priv(&secp, &derived_xprv);
        assert_eq!(
            derived_pubkey.inner, xpub.public_key,
            "Public key derivation mismatch"
        );

        // Add to the collection of key pairs
        key_pairs.push((private_key, derived_pubkey.into()));
    }

    key_pairs
}

/// Mine bitcoins to the descriptor address returning the coinbase
/// transaction in the block at cb_block_index.
pub fn mine_bitcoins(
    bitcoind: &BitcoinD,
    ms_descr: &Descriptor<PublicKey>,
    block_count: u64,
    cb_block_index: u64,
) -> Transaction {
    let address = ms_descr
        .address(miniscript::bitcoin::Network::Regtest)
        .expect("Failed to compute address");
    let block_hashes = bitcoind
        .client
        .generate_to_address(block_count, &address)
        .expect("Failed to generate to address");
    assert!(block_hashes.len() == block_count as usize);
    let block_hash = bitcoind
        .client
        .get_block(&block_hashes[cb_block_index as usize])
        .expect("Block hashes indexed out of bounds.");
    let coinbase_tx = block_hash
        .coinbase()
        .expect("No coinbase transaction in block???");

    coinbase_tx.clone()
}

/// Mine bitcoins to the provided address returning the coinbase
/// transaction in the block at cb_block_index.
pub fn mine_bitcoins_to_address(
    bitcoind: &BitcoinD,
    address: &Address,
    block_count: u64,
    cb_block_index: u64,
) -> Transaction {
    let block_hashes = bitcoind
        .client
        .generate_to_address(block_count, &address)
        .expect("Failed to generate to address");
    assert!(block_hashes.len() == block_count as usize);

    let block_hash = bitcoind
        .client
        .get_block(&block_hashes[cb_block_index as usize])
        .expect("Block hashes indexed out of bounds.");

    let coinbase_tx = block_hash
        .coinbase()
        .expect("No coinbase transaction in block???");

    coinbase_tx.clone()
}

/// Generates a new Regtest-checked address.
pub fn generate_new_checked_address(bitcoind: &BitcoinD) -> Address {
    let dest_address = bitcoind
        .client
        .get_new_address(
            None,
            Some(bitcoind::bitcoincore_rpc::json::AddressType::P2shSegwit),
        )
        .expect("Failed to get new address");
    let checked_addr = dest_address.assume_checked();

    checked_addr
}

/// Creates a spending transaction given the destination address,
/// amount to send, the transaction containing the output being spent
///  from, and the relative timelock that emcumbers the transaction
/// output being spent.
pub fn spending_tx(
    dest_addr: Address,
    amount: Amount,
    lock_tx: &Transaction,
    sequence: Sequence,
) -> Transaction {
    let output = TxOut {
        value: amount,
        script_pubkey: dest_addr.script_pubkey(),
    };

    let input = TxIn {
        previous_output: OutPoint {
            txid: lock_tx.compute_txid(),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::new(),
    };

    let mut spend_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    spend_tx.output.push(output);
    spend_tx.input.push(input);

    spend_tx
}

/// Generate a signature for unsigned transaction given the following:
/// the amount being spent
/// the private key used to sign the signature hash message once generated
/// the public key to verify the generated signature
pub fn generate_signature(
    unsigned_tx: &Transaction,
    secp: &Secp256k1<All>,
    ws: &Script,
    amount: Amount,
    private_key: PrivateKey,
    public_key: PublicKey,
) -> Signature {
    let mut cache = SighashCache::new(unsigned_tx);
    let sighash = cache
        .p2wsh_signature_hash(0, &ws, amount, EcdsaSighashType::All)
        .expect("Failed to compute sighash");
    let sighash_msg =
        Message::from_digest_slice(&sighash[..]).expect("Failed to create sighash message");

    let signature = secp.sign_ecdsa(&sighash_msg, &private_key.inner);

    assert!(secp
        .verify_ecdsa(&sighash_msg, &signature, &public_key.inner)
        .is_ok());

    Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    }
}

/// Helper function to create a PSBT
fn create_psbt(
    bitcoind: &BitcoinD,
    prev_outpoint: OutPoint,
    sequence: Option<u32>,
    output_address: String,
    amount: Amount,
) -> Result<String, BitcoindError> {
    let inputs = CreateRawTransactionInput {
        txid: prev_outpoint.txid,
        vout: prev_outpoint.vout,
        sequence,
    };

    let mut outputs = HashMap::new();
    outputs.insert(output_address, amount);

    let locktime = None;
    let replaceable = None;

    bitcoind
        .client
        .create_psbt(&vec![inputs], &outputs, locktime, replaceable)
        .map_err(|e| BitcoindError::CoreRpcError(e))
}

fn _spend_coinbase_utxo(bitcoind: &BitcoinD, coinbase_tx: &Transaction) {
    // 0. Mine n blocks to spend from coinbase UTXO. Generate to a random address
    //    at your height of interest instead of directly calling generate. Workaround
    //    generate call error.
    let rand_address_check = generate_new_checked_address(bitcoind);
    let _ = bitcoind
        .client
        .generate_to_address(99, &rand_address_check)
        .expect("Failed to mine to address.");

    // 1. broadcast transaction
    let broadcast_txid = bitcoind
        .client
        .send_raw_transaction(&*coinbase_tx)
        .expect("Failed to broadcast transaction");

    // 2. Mine n blocks to confirm
    let mine_res = bitcoind.client.generate(1, None).expect("Failed to mine");
    // 3. Assert spend_tx is in the blockchain
    let mined_block_hash = mine_res[0];
    let mined_block = bitcoind
        .client
        .get_block(&mined_block_hash)
        .expect("Failed to retrieve block");
    assert!(mined_block.txdata.contains(
        &bitcoind
            .client
            .get_raw_transaction(&broadcast_txid, Some(&mined_block_hash))
            .expect(&format!(
                "Transaction with ID {broadcast_txid} not in block {mined_block_hash}"
            ))
    ));
}

pub fn lock_tx(bitcoind: &BitcoinD, output_descr_address: String) -> Transaction {
    let coinbase_addr = generate_new_checked_address(&bitcoind);
    let coinbase_tx = mine_bitcoins_to_address(&bitcoind, &coinbase_addr, 101, 0);
    let amount = Amount::from_sat(coinbase_tx.output[0].value.to_sat() - 10_000);

    let lock_tx_str = create_psbt(
        &bitcoind,
        OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: 0,
        },
        None,
        output_descr_address,
        amount,
    )
    .expect("Failed to create lock PSBT");

    let signed_psbt_tx = bitcoind
        .client
        .wallet_process_psbt(
            &lock_tx_str,
            Some(true),
            Some(SigHashType::from(EcdsaSighashType::All)),
            None,
        )
        .expect("Failed to process PSBT");

    let finalized_lock_psbt = bitcoind
        .client
        .finalize_psbt(&signed_psbt_tx.psbt, Some(true))
        .expect("Failed to finalize PSBT");

    let finalized_lock_tx = finalized_lock_psbt
        .transaction()
        .unwrap()
        .expect("Failed to extract transaction from finalized PSBT.");

    finalized_lock_tx
}
