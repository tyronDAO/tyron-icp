mod bitcoin_api;
mod bitcoin_wallet;
mod ecdsa_api;
mod constants;
mod types;
mod provider;
mod http;
mod tests;

pub use crate::constants::*;
pub use crate::types::*;
pub use crate::provider::*;
pub use crate::http::*;
use candid::Principal;
use ic_cdk::api::management_canister::http_request::HttpResponse;
use ic_cdk::api::management_canister::http_request::TransformArgs;
use ic_cdk::{api::management_canister::bitcoin::{
    BitcoinNetwork, MillisatoshiPerByte,
}, query};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, update};
use ic_ckbtc_minter_tyron::address::get_ssi_derivation_path;
use ic_ckbtc_minter_tyron::address::public_key_to_p2wpkh;
use ic_ckbtc_minter_tyron::address::BitcoinAddress;
use ic_ckbtc_minter_tyron::lifecycle::upgrade::UpgradeArgs;
use ic_ckbtc_minter_tyron::updates::get_btc_address::init_ecdsa_public_key;
use ic_ckbtc_minter_tyron::updates::retrieve_btc::balance_of;
use ic_ckbtc_minter_tyron::updates::retrieve_btc::SyronLedger;
use ic_ckbtc_minter_tyron::updates::update_balance::btc_bal_update;
use ic_ckbtc_minter_tyron::updates::update_balance::syron_payment;
use ic_ckbtc_minter_tyron::updates::update_balance::syron_update;
use ic_ckbtc_minter_tyron::updates::update_balance::CollateralizedAccount;
use icrc_ledger_types::icrc1::account::Account;
use serde_json::Value;
use std::cell::{Cell, RefCell};

use ic_ckbtc_minter_tyron::{
    lifecycle::{
        self,
        init::MinterArg
    },
    state::{self, eventlog::Event, read_state},
    storage::record_event,
    tasks::{schedule_now, TaskType},
    updates::{
        self, get_btc_address::{self, GetBoxAddressArgs, SyronOperation}, get_withdrawal_account::compute_subaccount, update_balance::{UpdateBalanceError, UtxoStatus, get_collateralized_account}
    },
    MinterInfo
};

use icrc_ledger_types::icrc1::account::Subaccount;
use candid::candid_method;

struct TransferResult {
    tx_id: String,
    inscribed_amt: u64
}

async fn syron_transfer(
    txid: String,
    provider: u64,
    cycles_cost: u128,
    key_name: String,
    origin_derivation_path: Vec<Vec<u8>>,
    origin_address: String,
    dst_address: &str,
    requested_amt: u64,
    fee: u64
) -> Result<TransferResult, UpdateBalanceError> {
    // @dev Check BRC-20 inscribe-transfer UTXO
    let outcall = call_indexer_inscription(provider, txid.clone(), cycles_cost).await?;
    let outcall_json: Value = serde_json::from_str(&outcall).unwrap();

    // Verify inscription receiver address
    let receiver_address: String = outcall_json.pointer("/utxo/address")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if receiver_address != origin_address {
        return Err(UpdateBalanceError::GenericError{
            error_code: 304,
            error_message: format!("The inscription receiver address ({}) must be equal to the origin of the transfer ({})", receiver_address, origin_address),
        });
    }

    // Access the "amt" field in the "brc20" object
    let syron_inscription: String = outcall_json.pointer("/brc20/amt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // The Syron inscribed amount must be less than the limit or throw UpdateBalanceError::GenericError
    let syron_f64: f64 = syron_inscription.parse().unwrap_or(0.0);
    let syron_u64: u64 = (syron_f64 * 100_000_000 as f64) as u64;

    if syron_u64 > requested_amt {
        return Err(UpdateBalanceError::GenericError{
            error_code: 305,
            error_message: format!("The inscribed amount ({}) cannot exceed the withdrawal amount you requested ({}).", syron_f64, requested_amt/100_000_000),
        });
    }

    // @dev Send SYRON BRC-20 to the destination address

    let tx_id = bitcoin_wallet::syron_p2wpkh(
        key_name,
        origin_derivation_path,
        origin_address,
        &dst_address,
        txid,
        fee
    )
    .await?;

    Ok(TransferResult{
        tx_id,
        inscribed_amt: syron_u64
    })
}

/// Mint SUSD using P2WPKH - the transaction id must correspond to the required incribe-transfer UTXO
async fn mint(ssi: String, txid: String, cycles_cost: u128, provider: u64, amount: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @dev Read SYRON available balance (nonce #2)
    let balance = balance_of(SyronLedger::SUSD, &ssi, 2).await.unwrap();
    
    // amount cannot be higher than the balance
    if amount > balance {
        return Err(UpdateBalanceError::GenericError{
            error_code: 301,
            error_message: "Insufficient balance".to_string(),
        });
    }
    
    // SUSD amount cannot be lower than 20 cents
    if amount < 20_000_000 {
        return Err(UpdateBalanceError::GenericError{
            error_code: 302,
            error_message: format!("Amount ({}) is below the minimum", amount),
        });
    }
    
    let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());

    // if key is empty, throw error
    if key_name.is_empty() {
        return Err(UpdateBalanceError::GenericError{
            error_code: 303,
            error_message: "Key name is empty".to_string(),
        });
    }
    
    // @dev Get Syron Bitcoin address (The receiver of this transfer inscription must be equal to the Syron address)
    let minter_derivation_path = DERIVATION_PATH.with(|d| d.clone());
    
    let minter_public_key =
        ecdsa_api::ecdsa_public_key(key_name.clone(), minter_derivation_path.clone()).await;
    
    let syron_address = public_key_to_p2wpkh(&minter_public_key);

    // @dev Send SUSD to the user's wallet (SSI)
    let transfer = syron_transfer(
        txid,
        provider,
        cycles_cost,
        key_name,
        minter_derivation_path,
        syron_address,
        &ssi,
        amount,
        fee
    ).await;

    match transfer {
        Ok(transfer) => {
            // Update Syron USD Ledger
            // @dev Compute the new balance amount as the current balance less the SYRON inscription
            let new_balance = balance.checked_sub(transfer.inscribed_amt).unwrap_or(0);

            // do not consider any new balance below 2 cents @review amt
            if new_balance < 2_000_000 {
                // withdraw full balance @doc 2 is the nonce of the balance subaccount, and 3 the BRC-20 subaccount.
                match syron_update(&ssi, 2, Some(3), balance).await {
                    Ok(_) => {
                        ic_cdk::println!("Successful withdrawal of the full balance: {:?}", balance);
                        Ok(transfer.tx_id)
                    }
                    Err(err) => {
                        ic_cdk::println!("Double spending risk warning: {:?}", err);
                        Err(err) // @review save data in records to run book-keeping task by the system again
                    }
                }
            } else {
                match syron_update(&ssi, 2, Some(3), transfer.inscribed_amt).await {
                    Ok(_) => {
                        ic_cdk::println!("Successful withdrawal of the following balance: {:?}", transfer.inscribed_amt);
                        Ok(transfer.tx_id)
                    }
                    Err(err) => {
                        ic_cdk::println!("Double spending risk warning: {:?}", err);
                        Err(err) // @review save data in records to run book-keeping task by the system again
                    }
                }
            }
        }
        Err(err) => Err(err) 
    }
}

fn check_postcondition<T>(t: T) -> T {
    #[cfg(feature = "self_check")]
    ok_or_die(check_invariants());
    t
}

thread_local! {
    // The bitcoin network to connect to.
    //
    // When developing locally this should be `Regtest`.
    // When deploying to the IC this should be `Testnet`.
    // `Mainnet` is currently unsupported.

    // @network
    static NETWORK: Cell<BitcoinNetwork> = Cell::new(BitcoinNetwork::Testnet);

    // The derivation path to use for ECDSA secp256k1.
    static DERIVATION_PATH: Vec<Vec<u8>> = vec![];

    // The ECDSA key name.
    static KEY_NAME: RefCell<String> = RefCell::new(String::from(""));
}

#[init]
pub fn init(network: BitcoinNetwork, args: MinterArg) {
    NETWORK.with(|n| n.set(network));

    KEY_NAME.with(|key_name| {
        key_name.replace(String::from(match network {
            // For local development, we use a special test key with dfx.
            BitcoinNetwork::Regtest => "dfx_test_key",
            BitcoinNetwork::Mainnet => "key_1",
            // BitcoinNetwork::Signet => "sig_key_1",
            // On the IC we're using a test ECDSA key.
            _ => "test_key_1"
            
        }))
    });
    
    match args {
        MinterArg::Init(args) => {
            record_event(&Event::Init(args.clone()));
            lifecycle::init::init(args);
            schedule_now(TaskType::ProcessLogic);
            schedule_now(TaskType::RefreshFeePercentiles);
            // schedule_now(TaskType::DistributeKytFee);

            #[cfg(feature = "self_check")]
            ok_or_die(check_invariants())
        }
        MinterArg::Upgrade(_) => {
            panic!("expected InitArgs got UpgradeArgs");
        }
    }

    init_service_provider()
}

#[pre_upgrade]
fn pre_upgrade() {
    let network = NETWORK.with(|n| n.get());
    ic_cdk::storage::stable_save((network,)).expect("Saving network to stable store must succeed.");
}

#[post_upgrade]
fn post_upgrade(minter_arg: Option<UpgradeArgs>) {
    let network = ic_cdk::storage::stable_restore::<(BitcoinNetwork,)>()
        .expect("Failed to read network from stable memory.")
        .0;
    lifecycle::upgrade::post_upgrade(minter_arg);
    schedule_now(TaskType::ProcessLogic);
    schedule_now(TaskType::RefreshFeePercentiles);
    schedule_now(TaskType::DistributeKytFee);
    ic_cdk::println!("Post upgrade completed on Bitcoin {:?}", network);  
}

/// Returns the 100 fee percentiles measured in millisatoshi/byte.
/// Percentiles are computed from the last 10,000 transactions (if available).
#[update]
pub async fn get_current_fee_percentiles() -> Vec<MillisatoshiPerByte> {
    let network = NETWORK.with(|n| n.get());
    bitcoin_api::get_current_fee_percentiles(network).await
}
#[update]
pub async fn get_fee_percentile(percentile: u64) -> u64 {
    let network = NETWORK.with(|n| n.get());
    let fee_percentiles = bitcoin_api::get_current_fee_percentiles(network).await;
    fee_percentiles[percentile as usize]
}

async fn get_minter_address() -> Result<String, UpdateBalanceError> {
    // @dev Get the network's key name
    let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());
    // If the key name is empty, return an error
    if key_name.is_empty() {
        return Err(UpdateBalanceError::GenericError {
            error_code: 101,
            error_message: "Key name is empty".to_string(),
        });
    }

    // @dev Get derivation path
    let derivation_path = DERIVATION_PATH.with(|d| d.clone());
    
    Ok(bitcoin_wallet::get_p2wpkh_address(key_name, derivation_path).await)
}

/// Returns the P2WPKH address of this canister at a specific derivation path.
#[update]
pub async fn get_p2wpkh_address() -> String {
    match get_minter_address().await {
        Ok(address) => address,
        Err(err) => {
            // Handle the error here: log it & return a default value (empty string)
            ic_cdk::println!("Error getting minter address: {:?}", err);
            String::new() // Return an empty string
        }
    }
}

#[update]
pub async fn get_dao_addr() -> Vec<String> {
    let minter = match get_minter_address().await {
        Ok(address) => address,
        Err(err) => {
            // Handle the error here: log it & return a default value (empty array)
            ic_cdk::println!("Error getting minter address: {:?}", err);
            return vec![]; // Return an empty array
        }
        
    };
    let args: GetBoxAddressArgs = GetBoxAddressArgs {
        ssi: minter.clone(),
        op: get_btc_address::SyronOperation::Liquidation, // The treasury address is used for liquidations
    };

    init_ecdsa_public_key().await;
    let treasury = get_btc_address::get_box_address(args).await;

    let network = state::read_state(|s| (s.btc_network));
    let minter_addr = BitcoinAddress::parse(&minter, network).unwrap();
    let treasury_addr = BitcoinAddress::parse(&treasury, network).unwrap();
    
    let dao_addr = vec![minter_addr, treasury_addr];
    state::mutate_state(|s| {
        s.dao_addr = dao_addr
    });
    vec![minter, treasury]
}

#[update]
async fn susd_balance_of(ssi: String, nonce: u64) -> u64 {
    match balance_of(SyronLedger::SUSD, &ssi, nonce).await {
        Ok(bal) => bal,
        Err(_err) => 0
    }
}

#[update]
async fn sbtc_balance_of(ssi: String, nonce: u64) -> u64 {
    match balance_of(SyronLedger::BTC, &ssi, nonce).await {
        Ok(bal) => bal,
        Err(_err) => 0
    }
}

#[query]
async fn get_subaccount(nonce: u64, ssi: String) -> Subaccount {
    compute_subaccount(nonce, &ssi)
}

#[query]
fn get_minter_info() -> MinterInfo {
    read_state(|s| MinterInfo {
        kyt_fee: s.kyt_fee,
        min_confirmations: s.min_confirmations,
        retrieve_btc_min_amount: s.retrieve_btc_min_amount,
    })
}

#[update(name = "addServiceProvider")]// @review (mainnet),, guard = "require_add_provider")]
#[candid_method(rename = "addServiceProvider")]
fn add_service_provider(args: RegisterProviderArgs) -> u64 {
    register_provider(args)
}

#[query(name = "getServiceProviderMap")]// @review (mainnet), guard = "require_manage_or_controller")]
#[candid_method(query, rename = "getServiceProviderMap")]
fn get_service_provider_map() -> Vec<(ServiceProvider, u64)> {
    SERVICE_PROVIDER_MAP.with(|map| {
        map.borrow()
            .iter()
            .filter_map(|(k, v)| Some((k.try_into().ok()?, v)))
            .collect()
    })
}

#[update]
pub async fn get_inscription(txid: String, cycles_cost: u64, provider: u64) -> Result<String, UpdateBalanceError> {
    call_indexer_inscription(provider, txid.clone(), cycles_cost as u128).await
}

#[update]
pub async fn get_indexed_balance(id: String, provider: u64) -> Result<String, UpdateBalanceError> {
    call_indexer_balance(id, provider, 72_000_000).await
}

#[query(hidden = true)]
fn transform_request(args: TransformArgs) -> HttpResponse {
    do_transform_request(args)
}

#[query(hidden = true)]
fn transform_unisat_request(args: TransformArgs) -> HttpResponse {
    do_transform_unisat_request(args)
}

#[query(hidden = true)]
fn transform_bis_request(args: TransformArgs) -> HttpResponse {
    do_transform_bis_request(args)
}

#[query]
async fn get_box_address(args: GetBoxAddressArgs) -> String {
    // check_anonymous_caller();
    get_btc_address::get_box_address(args).await
}

#[update]
async fn update_ssi_balance(args: GetBoxAddressArgs) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    // check_anonymous_caller();
    check_postcondition(updates::update_balance::update_ssi_balance(args).await)
}

#[update]
pub async fn withdraw_susd(args: GetBoxAddressArgs, txid: String, cycles_cost: u64, provider: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @review (mainnet) automate provider config per network
    
    // @dev Verify args.op = GetSyron or throw erorr
    if args.op != SyronOperation::GetSyron {
        return Err(UpdateBalanceError::GenericError{
            error_code: 300,
            error_message: "Invalid operation".to_string(),
        });
    }

    // @dev Update Balance (the user's SDB MUST have BTC deposit confirmed)
    let _ = updates::update_balance::update_ssi_balance(args.clone()).await; //?;  @review (error) only propagate error if != NoNewUtxos

    // @dev Read SUSD available balance (nonce #2)
    let balance = susd_balance_of(args.ssi.clone(), 2).await;

    mint(args.ssi, txid, cycles_cost as u128, provider, balance, fee).await
}

#[update]
pub async fn syron_withdrawal(args: GetBoxAddressArgs, txid: String, cycles_cost: u64, provider: u64, amount: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @dev Verify args.op = GetSyron or throw erorr
    if args.op != SyronOperation::GetSyron {
        return Err(UpdateBalanceError::GenericError{
            error_code: 300,
            error_message: "Invalid operation".to_string(),
        });
    }

    mint(args.ssi, txid, cycles_cost as u128, provider, amount, fee).await
}

#[update]
async fn redeem_btc(args: GetBoxAddressArgs, txid: String, provider: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @dev Verify args.op = RedeemBitcoin or throw erorr
    if args.op != SyronOperation::RedeemBitcoin {
        return Err(UpdateBalanceError::GenericError{
            error_code: 400,
            error_message: "Invalid operation".to_string(),
        });
    }

    // Get the SDB address
    let sdb = get_btc_address::get_box_address(args.clone()).await;
    
    // @dev Get the Syron ledger's SUSD record of the user's SDB loan (subaccount with nonce 1) = SUSD[1]
    let ssi = (&args.ssi).to_string();
    
    let mut loan = susd_balance_of(ssi.clone(), 1).await; 
    // balance_of(SyronLedger::SUSD, &ssi, 1).await.map_err(|_| UpdateBalanceError::GenericError {
    //     error_code: 401,
    //     error_message: "Failed to get loan balance".to_string(),
    // })?;
    // Redeem/withdraw full amount of BTC deposits from SDB
    let amount = sbtc_balance_of(ssi.clone(), 1).await;
    
    // If the BTC deposit is 0, throw an error
    if amount == 0 {
        return Err(UpdateBalanceError::GenericError {
            error_code: 402,
            error_message: "Your SBTC deposit is zero, which is not allowed for redemptions.".to_string(),
        });
    }

    if loan != 0 {
        // @dev Check SUSD balance of the Safety Deposit Box
        // In the Syron SUSD ledger (nonce 2)
        let balance = susd_balance_of(ssi.clone(), 2).await;
        if balance != 0 {
            if balance < loan {
                // Use full balance to pay some of the loan
                match syron_update(&ssi, 2, None, balance).await {
                    Ok(_) => {
                        ic_cdk::println!("Successful usage of full balance ({:?}) to pay some of the loan.", balance);
                        loan -= balance;
                    }
                    Err(err) => return Err(err)
                }
            } else {
                // Use balance to pay 100% of the loan
                match syron_update(&ssi, 2, None, loan).await {
                    Ok(_) => {
                        ic_cdk::println!("Successful usage of balance ({:?}) to pay 100% of the loan.", balance);
                        loan = 0;
                    }
                    Err(err) => return Err(err)
                }
            }
        }
    }

    let mut syron_address = None;
    let mut tx_id = None;

    if loan != 0 {
        // @dev Read SUSD balance on Bitcoin L1 with the Tyron indexer (SYRON BRC-20)
        let syron_u64: u64 = match get_syron_balance(sdb.clone(), provider).await {
            Some(balance) if balance > 0 => balance,
            _ => {
                return Err(UpdateBalanceError::GenericError {
                    error_code: 403,
                    error_message: "Invalid balance from indexer".to_string(),
                });
            }
        };

        // SYRON BRC-20 balance must be at least the loan minus limit or throw UpdateBalanceError
        let limit = 2_000_000; // @governance
        if syron_u64 < loan - limit {
            return Err(UpdateBalanceError::GenericError{
                error_code: 404,
                error_message: "Insufficient SYRON BRC-20 deposited balance to redeem bitcoin".to_string(),
            });
        }
        // Verification done below (3.7)
        // if syron_u64 > loan {
        //     return Err(UpdateBalanceError::GenericError{
        //         error_code: 404,
        //         error_message: "The SUSD balance in your SDB exceeds the loan amount. Please withdraw SUSD and try again.".to_string(),
        //     });
        // }

        // Check BRC-20 incribe-transfer UTXO
        let outcall = call_indexer_inscription(provider, txid.clone(), 72_000_000).await?;
        let outcall_json: Value = serde_json::from_str(&outcall).unwrap();

        // Verify inscription's receiver address
        let receiver_address: String = outcall_json.pointer("/utxo/address")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        if receiver_address != sdb {
            return Err(UpdateBalanceError::GenericError{
                error_code: 405,
                error_message: format!("The inscription receiver address ({}) must be equal to your SDB ({})", receiver_address, sdb),
            });
        }

        // Access the "amt" field in the "brc20" object
        let syron_inscription: String = outcall_json.pointer("/brc20/amt")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

        // The Syron inscribed amount must be equal to the loan or throw UpdateBalanceError::GenericError
        let syron_f64: f64 = syron_inscription.parse().unwrap_or(0.0);
        let syron_u64_i: u64 = (syron_f64 * 100_000_000 as f64) as u64;

        if syron_u64_i < loan - limit || syron_u64_i > loan + limit || syron_u64_i > syron_u64 {
            return Err(UpdateBalanceError::GenericError{
                error_code: 406,
                error_message: format!("Incorrect inscribed amount {} of stablecoin to repay the loan, given a SYRON BRC-20 balance of {}.", syron_u64_i, syron_u64),
            });
        }
        // if syron_u64_i != syron_u64 {
        //     return Err(UpdateBalanceError::GenericError{
        //         error_code: 406,
        //         error_message: "Insufficient inscribed amount of stablecoin".to_string(),
        //     });
        // }
        
        // Get Syron Minter's Bitcoin address
        // let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());
        // if key_name.is_empty() {
        //     return Err(UpdateBalanceError::GenericError{
        //         error_code: 407,
        //         error_message: "Key name is empty".to_string(),
        //     });
        // }
        // let syron_derivation_path = DERIVATION_PATH.with(|d| d.clone());
        // let own_public_key =
        //     ecdsa_api::ecdsa_public_key(key_name.clone(), syron_derivation_path.clone()).await;
        // let syron_address = public_key_to_p2wpkh(&own_public_key);
        let minter_address = get_minter_address().await?;
        syron_address = Some(minter_address);
        tx_id = Some(txid);
    }

    // @dev Transfer bitcoin from SDB to wallet
    let tx_id = bitcoin_wallet::burn_p2wpkh(
        amount,
        &ssi,
        sdb,
        &ssi,
        syron_address,
        tx_id,
        fee
    ).await?;

    // @dev Update Syron ledgers of debtor @review (error)
    updates::update_balance::update_ssi_balance(args).await?;

    // let txid_bytes = tx_id.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
    // Ok(hex::encode(txid_bytes))
    Ok(tx_id)
}

#[update]
async fn redemption_gas(args: GetBoxAddressArgs) -> Result<u64, UpdateBalanceError> {
    // @dev Verify args.op = RedeemBitcoin or throw erorr
    if args.op != SyronOperation::RedeemBitcoin {
        return Err(UpdateBalanceError::GenericError{
            error_code: 500,
            error_message: "Invalid operation".to_string(),
        });
    }

    let ssi = (&args.ssi).to_string();
    let sdb = get_btc_address::get_box_address(args.clone()).await;

    let syron_derivation_path = DERIVATION_PATH.with(|d| d.clone());
    
    let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());

    // if empty, throw error
    if key_name.is_empty() {
        return Err(UpdateBalanceError::GenericError{
            error_code: 501,
            error_message: "Key name is empty".to_string(),
        });
    }

    let own_public_key =
        ecdsa_api::ecdsa_public_key(key_name.clone(), syron_derivation_path.clone()).await;
    
    let syron_address = public_key_to_p2wpkh(&own_public_key);

    let amount = sbtc_balance_of(ssi.clone(), 1).await;
    let btc_network = NETWORK.with(|n| n.get());
    
    let gas = bitcoin_wallet::gas_p2wpkh(
        amount,
        &ssi,
        btc_network,
        sdb,
        &ssi,
        &syron_address
    )
    .await;

    Ok(gas)
}

#[update]
async fn get_account(ssi: String) -> Result<CollateralizedAccount, UpdateBalanceError> {
    check_postcondition(get_collateralized_account(&ssi).await)
}

#[update]
async fn read_account(ssi: String) -> Vec<u64> {
    let btc_0 = sbtc_balance_of(ssi.clone(), 0).await;
    let btc_1 = sbtc_balance_of(ssi.clone(), 1).await;
    let susd_1 = susd_balance_of(ssi.clone(), 1).await;
    let susd_2 = susd_balance_of(ssi.clone(), 2).await;
    let susd_3 = susd_balance_of(ssi.clone(), 3).await;

    vec![btc_0, btc_1, susd_1, susd_2, susd_3]
}

#[update]
// @review the order of UTXOs is important to transfer the proper inscription
async fn liquidate(args: GetBoxAddressArgs, id: String, txid: String, provider: u64, fee: u64) -> Result<Vec<String>, UpdateBalanceError> {
    let ssi: &str = &args.ssi;
    
    // @dev Verify collateral ratio is below 12,000 basis points or throw error
    let collateralized_account = get_collateralized_account(ssi).await?;

    if collateralized_account.collateral_ratio > 12_000 {
        return Err(UpdateBalanceError::GenericError{
            error_code: 500,
            error_message: format!("Collateral ratio({}) is above 1,2", collateralized_account.collateral_ratio),
        });
    }

    let btc_1 = collateralized_account.btc_1;
    let susd_1 = collateralized_account.susd_1;

    let sdb_debtor = get_btc_address::get_box_address(args.clone()).await;

    let liquidator = GetBoxAddressArgs {
        ssi: id.clone(),
        op: get_btc_address::SyronOperation::Liquidation,
    };

    let sdb_liquidator = get_btc_address::get_box_address(liquidator).await;

    // @dev Check the liquidator's SYRON BRC-20 balance in their safety deposit box with the Tyron indexer
    let syron_u64: u64 = match get_syron_balance(sdb_liquidator.clone(), provider).await {
        Some(balance) => balance,
        None => {
            return Err(UpdateBalanceError::GenericError{
                error_code: 501,
                error_message: "Invalid balance".to_string(),
            });
        }
    };

    // Liquidator's balance must be at least >= debtor's SUSD[1] OR throw UpdateBalanceError
    if syron_u64 < susd_1 {
        return Err(UpdateBalanceError::GenericError{
            error_code: 502,
            error_message: format!("Insufficient balance ({}) in the liquidator's account to liquidate the debtor", syron_u64)
        });
    }

    // @dev Transfer syron from liquidator's SDB to minter and bitcoin from debtor's SDB to the user's wallet (liquidator)
    let mut res: Vec<String> = Vec::new();

    let cycles_cost = 72_000_000;

    let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());
     
    let minter_derivation_path = DERIVATION_PATH.with(|d| d.clone());
    let dst_address = bitcoin_wallet::get_p2wpkh_address(key_name.clone(), minter_derivation_path).await;

    let sdb_subaccount = compute_subaccount(1, &id);
    let account = Account {
        owner: ic_cdk::id(),
        subaccount: Some(sdb_subaccount)
    };
    let origin_derivation_path: Vec<Vec<u8>> = get_ssi_derivation_path(&account, &id).into_iter().map(|index| index.0).collect();

    let payment = syron_transfer(
        txid,
        provider,
        cycles_cost,
        key_name.clone(),
        origin_derivation_path,
        sdb_liquidator,
        &dst_address,
        susd_1,
        //@review update balance from syron deposits to make sure that the liquidator has enough to pay
        fee
    ).await?;
    res.push(payment.tx_id);
    
    let tx_id = match bitcoin_wallet::liquidate_p2wpkh(
        btc_1,
        ssi,
        sdb_debtor,
        &id,
        fee
    )
    .await {
        Ok(tx_id) => tx_id,
        Err(err) => return Err(err)
    };

    let txid_bytes = tx_id.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
    res.push(hex::encode(txid_bytes));

    // 5. Update Syron ledgers (debtor)
    updates::update_balance::update_ssi_balance(args).await?;

    Ok(res)
}

fn check_anonymous_caller() {
    if ic_cdk::caller() == Principal::anonymous() {
        panic!("anonymous caller not allowed")
    }
}

#[update]
pub async fn send_syron(args: GetBoxAddressArgs, recipient: String, amount: u64) -> Result<Vec<u64>, UpdateBalanceError> {
    check_anonymous_caller();

    // @dev Verify args.op = Payment or throw erorr
    if args.op != SyronOperation::Payment {
        return Err(UpdateBalanceError::GenericError{
            error_code: 600,
            error_message: "Invalid operation".to_string(),
        });
    }

    // @dev Set Bitcoin network
    let network = state::read_state(|s| (s.btc_network));

    let ssi = args.ssi;
    let sender = BitcoinAddress::parse(&ssi, network).unwrap();
    let receiver = BitcoinAddress::parse(&recipient, network).unwrap();

    // @dev Read Syron SUSD available balance (nonce #2)
    let balance = balance_of(SyronLedger::SUSD, &ssi, 2).await.unwrap();

    // amount cannot be higher than the balance
    if amount > balance {
        return Err(UpdateBalanceError::GenericError{
            error_code: 601,
            error_message: format!("Insufficient balance {}", balance)
        });
    }

    match syron_payment(sender, receiver, amount, None).await {
        Ok(res) => Ok(res),
        Err(err) => Err(err)
    }
}

#[update]
pub async fn buy_btc(args: GetBoxAddressArgs, amount: u64, btc_amount: u64, fee: u64) -> Result<Vec<String>, UpdateBalanceError> {
    check_anonymous_caller();

    // @dev Verify args.op = Payment or throw erorr
    if args.op != SyronOperation::Payment {
        return Err(UpdateBalanceError::GenericError{
            error_code: 700,
            error_message: "Invalid operation".to_string(),
        });
    }

    // amount cannot be lower than $1 SUSD @governance
    if amount < 100_000_000 {
        return Err(UpdateBalanceError::GenericError{
            error_code: 701,
            error_message: format!("Amount {} is below the minimum", amount),
        });
    }

    // @dev Set Bitcoin network
    let network = state::read_state(|s| (s.btc_network));

    let ssi = args.ssi;
    let sender = BitcoinAddress::parse(&ssi, network).unwrap();

    // @dev Read Syron SUSD available balance (nonce #2)
    let balance = balance_of(SyronLedger::SUSD, &ssi, 2).await.unwrap();

    // SUSD amount cannot be higher than the balance
    if amount > balance {
        return Err(UpdateBalanceError::GenericError{
            error_code: 702,
            error_message: format!("Insufficient SUSD balance ({}) susd-sats", balance)
        });
    }

    // @dev The recipient is the DAO Treasury address
    let dao_addr = state::read_state(|s| s.dao_addr.clone());
    let receiver = &dao_addr[1];
    let treasury_address = receiver.display(network);
    
    match syron_payment(sender.clone(), receiver.clone(), amount, Some(btc_amount)).await {
        Ok(res) => {
            ic_cdk::println!("SUSD transfer result: [sbtc_index, susd_index] = {:?}", res);
            // let payment_result = res.into_iter().map(|s| s.to_string()).collect();
            
            // @dev Read the Treasury's Syron SUSD balance (nonce #2)
            let treasury_balance = balance_of(SyronLedger::SUSD, &treasury_address, 2).await.unwrap();
            ic_cdk::println!("The Treasury's SUSD balance is: {:?} susd-sats", treasury_balance);
            
            // @dev Read BTC available balance (nonce #0)
            let bitcoin_amount = balance_of(SyronLedger::BTC, &ssi, 0).await.unwrap();
            
            // "bitcoin_amount" must be at least the minimum BTC amount requested by the user ("btc")
            if bitcoin_amount < btc_amount {
                return Err(UpdateBalanceError::GenericError{
                    error_code: 703,
                    error_message: format!(
                        "Insufficient BTC balance. Available: {} sats, Minimum Required: {} sats",
                        bitcoin_amount, btc_amount
                    )
                });
            }
            ic_cdk::println!("The user has a BTC credit balance of {:?} satoshis", bitcoin_amount);

            match bitcoin_wallet::btc_p2wpkh(
                dao_addr,
                sender,
                bitcoin_amount,
                fee
            )
            .await {
                Ok(p2wpkh_result) => {
                    match btc_bal_update(&ssi, 0, None, bitcoin_amount).await {
                        Ok(res2) => {
                            ic_cdk::println!("BTC L1 transaction result: {:?}", p2wpkh_result);
                            let mut result: Vec<String> = p2wpkh_result;

                            let sbtc_index: String = res2.into_iter().map(|s| s.to_string()).collect();
                            ic_cdk::println!("Successful removal of the following BTC credit balance from the Syron Bitcoin ledger: {:?} sats, with sbtc_index {}.", bitcoin_amount, sbtc_index);
                            result.push(format!("bitcoin_amount: {:?}", bitcoin_amount));
                            
                            // @dev Send the updated balance in the transaction result
                            let new_balance = balance.checked_sub(amount).unwrap_or(0);
                            result.push(format!("susd_balance: {:?}", new_balance));

                            Ok(result)
                        },
                        Err(err) => {
                            ic_cdk::println!("Double spending risk warning: {:?}", err);
                            Err(err)
                        }
                    }
                },
                Err(err) => Err(err)    
            }
        },
        Err(err) => Err(err)
    }
}

// @dev-mode
/// Returns the UTXOs of the given bitcoin address.
#[update]
pub async fn get_utxo_txids(address: String) -> Vec<String> {
    let network = NETWORK.with(|n| n.get());
    let response = bitcoin_api::get_utxos(network, address).await;
    let utxos = response.utxos;

    let mut res_utxos = [].to_vec();

    for utxo in &utxos {
        let txid_bytes = utxo.outpoint.txid.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
        let txid_hex = hex::encode(txid_bytes);
        res_utxos.push(txid_hex)
    };
    res_utxos
}
