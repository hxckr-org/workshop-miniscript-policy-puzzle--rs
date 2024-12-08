use bitcoind::bitcoincore_rpc::RpcApi;
use workshop_miniscript_policy_puzzle__rs::setup_bitcoind;

#[test]
fn test_bitcoind() {
    let bitcoind_client = setup_bitcoind().unwrap();

    let blockchain_info = bitcoind_client.client.get_blockchain_info().unwrap();
    assert_eq!(0, blockchain_info.blocks);
}