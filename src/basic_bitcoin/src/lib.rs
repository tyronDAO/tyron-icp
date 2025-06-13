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
use bitcoin_wallet::fetch_bitcoin_network;
use candid::CandidType;
use candid::Principal;
use ic_cdk::api::management_canister::{
    http_request::{HttpResponse, TransformArgs},
    bitcoin::{BitcoinNetwork, MillisatoshiPerByte}
};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, update, query};
use ic_ckbtc_minter_tyron::queries::RetrieveBtcStatusRequest;
use ic_ckbtc_minter_tyron::state::RetrieveBtcStatusV2;
use ic_ckbtc_minter_tyron::updates::retrieve_btc;
use ic_ckbtc_minter_tyron::updates::retrieve_btc::RetrieveBtcArgs;
use ic_ckbtc_minter_tyron::updates::retrieve_btc::RetrieveBtcError;
use ic_ckbtc_minter_tyron::updates::retrieve_btc::RetrieveBtcOk;
use icrc_ledger_types::icrc1::account::Account;
use serde::Deserialize;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use ic_btc_interface::Utxo;
use ic_ckbtc_minter_tyron::{
    estimate_fee_per_vbyte,
    address::{ get_ssi_derivation_path, public_key_to_p2wpkh, BitcoinAddress },
    lifecycle::{ self, init::MinterArg, upgrade::UpgradeArgs },
    state::{self, eventlog::Event, read_state},
    storage::{self},
    tasks::{schedule_now, TaskType},
    updates::{
        get_btc_address::{self, init_ecdsa_public_key, GetBoxAddressArgs, SyronOperation},
        get_withdrawal_account::compute_subaccount,
            retrieve_btc::{balance_of, SyronLedger},
        update_balance::{self, UpdateBalanceError, UtxoStatus, get_collateralized_account}
    },
    management::{self},
    MinterInfo
};

use icrc_ledger_types::icrc1::account::Subaccount;
use candid::candid_method;
use std::time::Duration;
use ic_cdk_timers::set_timer_interval;

struct TransferResult {
    tx_id: String,
    inscribed_amt: u64
}

/// The response returned for a request to get the UTXOs of a given address.
#[derive(CandidType, Debug, Deserialize, PartialEq, Eq, Clone)]
pub struct GetRunesMinter {
    pub runes_utxos: Vec<Utxo>,
    pub sats_utxos: Vec<Utxo>,
}

#[cfg(feature = "self_check")]
fn ok_or_die(result: Result<(), String>) {
    if let Err(msg) = result {
        ic_cdk::println!("{}", msg);
        ic_cdk::trap(&msg);
    }
}

/// Checks that ckBTC minter state internally consistent.
#[cfg(feature = "self_check")]
fn check_invariants() -> Result<(), String> {
    use ic_ckbtc_minter_tyron::state::eventlog::replay;

    read_state(|s| {
        s.check_invariants()?;

        let events: Vec<_> = storage::events().collect();
        let recovered_state = replay(events.clone().into_iter())
            .unwrap_or_else(|e| panic!("failed to replay log {:?}: {:?}", events, e));

        recovered_state.check_invariants()?;

        // A running timer can temporarily violate invariants.
        if !s.is_timer_running {
            s.check_semantically_eq(&recovered_state)?;
        }

        Ok(())
    })
}

// @review (alpha)
// This function is called by the timer task to process pending requests and distribute fees.
// It is not a part of the public API, but it is used internally to ensure that the minter
// processes requests and distributes fees at regular intervals.
// #[export_name = "canister_global_timer"]
// fn timer() {
//     #[cfg(feature = "self_check")]
//     ok_or_die(check_invariants());

//     ic_cdk::println!("timer called");

//     ic_ckbtc_minter_tyron::timer();
// }

async fn syron_transfer(
    txid: String,
    provider: u64,
    cycles_cost: u128,
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
async fn mint_brc20(ssi: String, txid: String, cycles_cost: u128, provider: u64, amount: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @dev Read SYRON available balance (nonce #2)
    let balance = balance_of(SyronLedger::SYRON, &ssi, 2).await.unwrap();
    
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
    
    // let key_name = KEY_NAME.with(|kn| kn.borrow().to_string());
    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());

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
                match update_balance::syron_update(&ssi, 2, Some(3), balance).await {
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
                match update_balance::syron_update(&ssi, 2, Some(3), transfer.inscribed_amt).await {
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

/// retrieve syron runes (request withdrawal on bitcoin)
async fn retrieve_runes(ssi: String, amount: u64) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    // @dev read syron available balance (nonce 2)
    let balance = balance_of(SyronLedger::SYRON, &ssi, 2).await.unwrap();
    
    // amount cannot be higher than the balance
    if amount > balance {
        return Err(RetrieveBtcError::GenericError{
            error_code: 3010,
            error_message: format!("Insufficient balance ({}) for the requested amount ({})", balance, amount),
        });
    }
    
    // syron amount cannot be lower than 20 cents @review (governance)
    if amount < 20_000_000 {
        return Err(RetrieveBtcError::GenericError{
            error_code: 3020,
            error_message: format!("Amount ({}) is below the minimum", amount),
        });
    }

    let args = RetrieveBtcArgs {
        amount,
        address: ssi
    };

    retrieve_btc(args, 2, 4).await
}

/// Update runes minter balance
async fn check_runes_minter_utxos(cycles_cost: u128) -> Result<(Vec<Utxo>, Vec<Utxo>), UpdateBalanceError> {
    // @dev get minter utxos
    let (runes_minter, network, min_confirmations) = state::read_state(|s: &state::MinterState| (s.dao_addr[2].display(s.btc_network), s.btc_network, s.min_confirmations));
    let utxos_response = management::get_utxos(network, &runes_minter, min_confirmations, management::CallSource::Client).await?;
    let mut minter_utxos: Vec<Utxo> = utxos_response.utxos;

    // @dev iterate over the utxos and send each transaction id to the outcall

    let mut utxos1: Vec<Utxo> = Vec::new();
    let mut utxos2: Vec<Utxo> = Vec::new();
    
    for utxo in &mut minter_utxos {
        let outcall = call_indexer_runes_balance(utxo.clone(), cycles_cost).await?;
        ic_cdk::println!("runes minter utxo balance outcall ({:?}) for utxo ({:?})", outcall, utxo);

        let outcall_json: Value = serde_json::from_str(&outcall).unwrap();

        let amount_str = outcall_json["amount"].as_str().expect("amount should be a string");
        let amount_u64: u64 = amount_str.parse().expect("amount should be a valid u64");

        if amount_u64 == 0 {
            utxos1.push(utxo.clone());
        } else {
            utxo.value = amount_u64;
            utxos2.push(utxo.clone());
        }
    }

    return Ok((utxos1, utxos2));
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

// @note a short interval to act as a heartbeat for the task scheduler.
const HEARTBEAT_INTERVAL_SECS: u64 = 1;

#[init]
pub fn init(args: MinterArg) {
    match args {
        MinterArg::Init(args) => {
            storage::record_event(&Event::Init(args.clone()));
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

    init_service_provider();
    
    set_timer_interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS), || {
        //ic_cdk::println!("--- HEARTBEAT TIMER FIRED at timestamp: {} ---", ic_cdk::api::time());

        ic_ckbtc_minter_tyron::timer();
    });

    ic_cdk::println!("Canister initialization completed");  
}

#[pre_upgrade]
fn pre_upgrade() {
    // @review (upgrade)
    // let network = NETWORK.with(|n| n.get());
    // ic_cdk::storage::stable_save((network,)).expect("Saving network to stable store must succeed.");
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
    
    set_timer_interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS), || {
        ic_ckbtc_minter_tyron::timer();
    });

    ic_cdk::println!("Post upgrade completed on Bitcoin {:?}", network);  
}

/// Returns the 100 fee percentiles measured in millisatoshi/byte.
/// Percentiles are computed from the last 10,000 transactions (if available).
#[update]
pub async fn get_current_fee_percentiles() -> Vec<MillisatoshiPerByte> {
    let btc_network = fetch_bitcoin_network().await;
    let opt1 = bitcoin_api::get_current_fee_percentiles(btc_network).await;

    let opt2 = estimate_fee_per_vbyte().await.unwrap_or(0);

    vec![opt1[50], opt2]
}

#[update]
pub async fn get_fee_percentile(percentile: u64) -> u64 {
    let btc_network = fetch_bitcoin_network().await;
    let fee_percentiles = bitcoin_api::get_current_fee_percentiles(btc_network).await;
    fee_percentiles[percentile as usize]
}

async fn get_minter_address() -> Result<String, UpdateBalanceError> {
    // @dev Get derivation path
    let derivation_path = DERIVATION_PATH.with(|d| d.clone());
    
    Ok(bitcoin_wallet::get_p2wpkh_address(derivation_path).await)
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
    let brc20_minter = match get_minter_address().await {
        Ok(address) => address,
        Err(err) => {
            // Handle the error here: log it & return a default value (empty array)
            ic_cdk::println!("Error getting minter address: {:?}", err);
            return vec![]; // Return an empty array
        }
        
    };
    let treasury_args: GetBoxAddressArgs = GetBoxAddressArgs {
        ssi: brc20_minter.clone(),
        op: get_btc_address::SyronOperation::Liquidation, // The treasury address is used for liquidations
    };

    init_ecdsa_public_key().await;
    let treasury = get_btc_address::get_box_address(treasury_args).await;
    
    let runes_args: GetBoxAddressArgs = GetBoxAddressArgs {
        ssi: treasury.clone(),
        op: get_btc_address::SyronOperation::GetSyron, // The runes address is used for minting
    };

    let runes_minter = get_btc_address::get_box_address(runes_args).await;

    let network = state::read_state(|s| (s.btc_network));
    let minter_addr = BitcoinAddress::parse(&brc20_minter, network).unwrap();
    let treasury_addr = BitcoinAddress::parse(&treasury, network).unwrap();
    let runes_minter_addr = BitcoinAddress::parse(&runes_minter, network).unwrap();
    
    let dao_addr = vec![minter_addr, treasury_addr, runes_minter_addr];
    state::mutate_state(|s| {
        s.dao_addr = dao_addr
    });
    vec![brc20_minter, treasury, runes_minter]
}

#[update]
async fn susd_balance_of(ssi: String, nonce: u64) -> u64 {
    match balance_of(SyronLedger::SYRON, &ssi, nonce).await {
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
    check_postcondition(update_balance::update_ssi_balance(args).await)
}

/// @dev Withdraw full balance of SUSD
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
    let _ = update_balance::update_ssi_balance(args.clone()).await; //?;  @review (error) only propagate error if != NoNewUtxos

    // @dev Read SUSD available balance (nonce #2)
    let balance = susd_balance_of(args.ssi.clone(), 2).await;
    
    mint_brc20(args.ssi, txid, cycles_cost as u128, provider, balance, fee).await    
}

#[update]
pub async fn syron_withdrawal(args: GetBoxAddressArgs, amount: u64, txid: String, cycles_cost: u64, provider: u64, fee: u64) -> Result<String, UpdateBalanceError> {
    // @dev Verify args.op = GetSyron or throw erorr
    if args.op != SyronOperation::GetSyron {
        return Err(UpdateBalanceError::GenericError{
            error_code: 300,
            error_message: "Invalid operation".to_string(),
        });
    }

    // @dev mint syron brc-20 - the transaction id must correspond to the required incribe-transfer utxo
    mint_brc20(args.ssi, txid, cycles_cost as u128, provider, amount, fee).await
}

#[update]
pub async fn syron_withdrawal_runes(args: GetBoxAddressArgs, amount: u64) -> Result<RetrieveBtcOk, RetrieveBtcError> {
    // @dev Verify args.op = GetSyron or throw erorr
    if args.op != SyronOperation::GetSyron {
        return Err(RetrieveBtcError::GenericError{
            error_code: 300,
            error_message: "Invalid operation".to_string(),
        });
    }

    // @dev mint syron runes
    let _ = update_balance::update_ssi_balance(args.clone()).await;
    retrieve_runes(args.ssi, amount).await
}

#[query]
fn retrieve_btc_status_v2(req: RetrieveBtcStatusRequest) -> RetrieveBtcStatusV2 {
    read_state(|s| s.retrieve_btc_status_v2(req.block_index))
}

/// add utxos of the runes minter
#[update]
pub async fn update_runes_minter(cycles_cost: u64) -> Result<Vec<UtxoStatus>, UpdateBalanceError> {
    let runes_minter_utxos = check_runes_minter_utxos(cycles_cost as u128).await?;
    update_balance::update_runes_balance(runes_minter_utxos).await
}

#[query]
pub async fn read_runes_minter() -> GetRunesMinter {
    let (runes_utxos, sats_utxos) = state::read_state(|s: &state::MinterState| (s.available_utxos.clone(), s.available_sats_utxos.clone()));
    ic_cdk::println!("runes utxos: {:?}", runes_utxos);
    ic_cdk::println!("sats utxos: {:?}", sats_utxos);

    GetRunesMinter {
        runes_utxos: runes_utxos.into_iter().collect(),
        sats_utxos: sats_utxos.into_iter().collect()
    }
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
    // balance_of(SyronLedger::SYRON, &ssi, 1).await.map_err(|_| UpdateBalanceError::GenericError {
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
                match update_balance::syron_update(&ssi, 2, None, balance).await {
                    Ok(_) => {
                        ic_cdk::println!("Successful usage of full balance ({:?}) to pay some of the loan.", balance);
                        loan -= balance;
                    }
                    Err(err) => return Err(err)
                }
            } else {
                // Use balance to pay 100% of the loan
                match update_balance::syron_update(&ssi, 2, None, loan).await {
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
    update_balance::update_ssi_balance(args).await?;

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
    let btc_network = fetch_bitcoin_network().await;
    
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
async fn get_account(ssi: String) -> Result<update_balance::CollateralizedAccount, UpdateBalanceError> {
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

    let minter_derivation_path = DERIVATION_PATH.with(|d| d.clone());
    let dst_address = bitcoin_wallet::get_p2wpkh_address(minter_derivation_path).await;

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
    update_balance::update_ssi_balance(args).await?;

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
    let balance = balance_of(SyronLedger::SYRON, &ssi, 2).await.unwrap();

    // amount cannot be higher than the balance
    if amount > balance {
        return Err(UpdateBalanceError::GenericError{
            error_code: 601,
            error_message: format!("Insufficient balance {}", balance)
        });
    }

    match update_balance::syron_payment(sender, receiver, amount, None).await {
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
    let balance = balance_of(SyronLedger::SYRON, &ssi, 2).await.unwrap();

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
    
    match update_balance::syron_payment(sender.clone(), receiver.clone(), amount, Some(btc_amount)).await {
        Ok(res) => {
            ic_cdk::println!("SUSD transfer result: [sbtc_index, susd_index] = {:?}", res);
            // let payment_result = res.into_iter().map(|s| s.to_string()).collect();
            
            // @dev Read the Treasury's Syron SUSD balance (nonce #2)
            let treasury_balance = balance_of(SyronLedger::SYRON, &treasury_address, 2).await.unwrap();
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
                    match update_balance::btc_bal_update(&ssi, 0, None, bitcoin_amount).await {
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
    let btc_network = fetch_bitcoin_network().await;
    let response = bitcoin_api::get_utxos(btc_network, address).await;
    let utxos = response.utxos;

    let mut res_utxos = [].to_vec();

    for utxo in &utxos {
        let txid_bytes = utxo.outpoint.txid.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
        let txid_hex = hex::encode(txid_bytes);
        res_utxos.push(txid_hex)
    };
    res_utxos
}

#[update]
pub async fn get_btc_exchange_rate(symbol: String) -> u64 {
    match management::fetch_btc_exchange_rate(symbol).await {
        Ok(xrc_res) => {
            ic_cdk::println!("XRC response: {:?}", xrc_res);
            match xrc_res {
                Ok(xr) => {
                    xr.rate
                },
                Err(_err) => {
                    0
                }
            }

        }
        Err(err) => {
            ic_cdk::println!("Error calling the Exchange Rate Canister: {:?}", err);
            0
        }
    }
}