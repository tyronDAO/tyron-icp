//! A demo of a very bare-bones bitcoin "wallet".
//!
//! The wallet here showcases how bitcoin addresses can be be computed
//! and how bitcoin transactions can be signed. It is missing several
//! pieces that any production-grade wallet would have, including:
//! * Caching spent UTXOs so that they are not reused in future transactions.
//! * Option to set the fee.

use crate::{bitcoin_api, ecdsa_api};
use bitcoin::network;
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::{
    blockdata::{script::Builder, witness::Witness},
    hashes::Hash,
    Address, AddressType, EcdsaSighashType, OutPoint, Script, Transaction, TxIn, TxOut, Txid,
};
use candid::error;
use ic_btc_interface::{GetBalanceError, Network};
use ic_cdk::api::management_canister::bitcoin::{MillisatoshiPerByte, BitcoinNetwork, Satoshi, Utxo,  Outpoint};
use ic_cdk::print;
use ic_ckbtc_minter_tyron::address::{derive_ssi_public_key, get_ssi_derivation_path, ssi_derivation_path, BitcoinAddress};
use ic_ckbtc_minter_tyron::logs::P1;
use ic_ckbtc_minter_tyron::management::{get_utxos, Reason};
use ic_ckbtc_minter_tyron::state::read_state;
use ic_ckbtc_minter_tyron::updates::get_withdrawal_account::compute_subaccount;
use ic_ckbtc_minter_tyron::updates::update_balance::UpdateBalanceError;
use ic_ckbtc_minter_tyron::{
    state,
    tx::{self, SignedTransaction, UnsignedInput, UnsignedTransaction, SignedInput},
    management::{sign_with_ecdsa, CallError, CallSource},
    signature::EncodedSignature,
    address::public_key_to_p2wpkh
};
use icrc_ledger_types::icrc1::account::Account;
use sha2::Digest;
use std::str::FromStr;
use std::thread::sleep;
use serde_bytes::ByteBuf;
use ic_management_canister_types::DerivationPath;
use ic_canister_log::log;
use std::fmt;
use regex;

const SIG_HASH_TYPE: EcdsaSighashType = EcdsaSighashType::All;

struct DisplayOutpoint<'a>(pub &'a Outpoint);

impl fmt::Display for DisplayOutpoint<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "{:?}:{}", self.0.txid, self.0.vout)
    }
}

/// Returns the P2WPKH address of this canister at the given derivation path.
pub(crate) async fn get_p2wpkh_address(
    derivation_path: Vec<Vec<u8>>,
) -> String {
    // Fetch the public key of the given derivation path
    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());
    let public_key = ecdsa_api::ecdsa_public_key(key_name, derivation_path).await;

    public_key_to_p2wpkh(&public_key)
}

pub(crate) async fn syron_p2wpkh(
    origin_derivation_path: Vec<Vec<u8>>,
    origin_address: String,
    dst_address: &str,
    tx_id: String,
    min_fee: u64    
) -> Result<String, UpdateBalanceError> {
    // @dev Set Bitcoin network
    let network =
        state::read_state(|s| (s.btc_network));
    let btc_network: BitcoinNetwork = match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    let fee_per_byte = select_fee_per_byte(btc_network, min_fee).await;

    // @dev Fetch sender's public key, address & UTXOs
    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());
    let own_public_key =
        ecdsa_api::ecdsa_public_key(key_name.clone(), origin_derivation_path.clone()).await;

    // Note that pagination may have to be used to get all UTXOs for the given address.
    // For the sake of simplicity, it is assumed here that the `utxo` field in the response
    // contains all UTXOs.
    let own_utxos: Vec<Utxo> =
        bitcoin_api::get_utxos(btc_network, origin_address.clone())
        .await
        .utxos;

    // let own_utxos: Vec<ic_btc_interface::Utxo> =
    // get_utxos(network, &own_address, 1, CallSource::Client) // @review (mainnet) min confirmations
    // .await
    // .unwrap().utxos;

    // for utxo in &own_utxos {
    //     log!(
    //         P1,
    //         "Minter UTXO: {}",
    //         DisplayOutpoint(&utxo.outpoint)
    //     );
    // }

    let mut option_utxo: Option<Utxo> = None;
    let mut fee_utxos = own_utxos.clone();

    // @dev Remove the UTXO that has the minter's SYRON balance inscription & every UTXO with a value less than 600 satoshis.
    for index in (0..fee_utxos.len()).rev() {
        let utxo = &fee_utxos[index];

        let txid_bytes = utxo.outpoint.txid.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
        let txid_hex = hex::encode(txid_bytes);

        // @network
        if txid_hex == "1cd2d3ef9657b6c2894d45e8769d76d63a7c6a66247aacf8c4b6d6d8fb614970".to_string()
        || txid_hex == "3c9890c6ed47c400ee68403fcf46641d5f30154df124b885e93d17ea50c76df7".to_string()
        || utxo.value < 600 {
            fee_utxos.remove(index);
        }
    }

    // @dev Select the UTXO that has the required transfer inscribed.
    for (index, utxo) in own_utxos.iter().enumerate() {
        // let outpoint = Outpoint {
        //     txid: utxo.outpoint.txid.as_ref().to_vec(),
        //     vout: utxo.outpoint.vout
        // };

        log!(
            P1,
            "UTXO: {}",
            DisplayOutpoint(&utxo.outpoint)
        );

        let txid_bytes = utxo.outpoint.txid.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
        let txid_hex = hex::encode(txid_bytes);

        if txid_hex == tx_id {
            // let ssi_utxo = Utxo {
            //     outpoint,
            //     value: utxo.value,
            //     height: utxo.height
            // };
            option_utxo = Some(utxo.clone());
            // fee_utxos.remove(index); @dev Removed already in previous iteration @protocol Inscription UTXO value must be less than 600 satoshis
            break
        }
    }

    let select_utxo = option_utxo.expect("No matching UTXO found in the SYRON minter.");

    let syron_btc_address = BitcoinAddress::parse(&origin_address, network).unwrap();
    let dst_address = BitcoinAddress::parse(&dst_address, network).unwrap();
    
    // @dev Builds the transaction that sends the selected UTXO (inscribe-transfer) to the destination address.
    let transaction = build_unsigned_mint(
        &own_public_key,
        syron_btc_address,
        select_utxo,
        &fee_utxos,
        dst_address,
        fee_per_byte,
    )
    .await?;

    // Sign the transaction.
    let signed_transaction: SignedTransaction = sign_transaction_p2wpkh(
        &own_public_key,
        transaction.clone(),
        origin_derivation_path,
    )
    .await.map_err(|err| UpdateBalanceError::CallError{method: err.method().to_string(), reason: Reason::to_string(err.reason())})?;

    let concatenated_result = format!(
        "Fee per byte: {} && Transaction ID: {}",
        fee_per_byte,
        transaction.txid().to_string(),
    );

    let signed_transaction_bytes = signed_transaction.serialize();
    match bitcoin_api::send_transaction(btc_network, signed_transaction_bytes.clone()).await {
        Ok(()) => Ok(concatenated_result),
        Err(err) => return Err(err)
    }
}

pub(crate) async fn burn_p2wpkh(
    amount: u64,
    ssi: &str,
    sdb: String,
    dst_address: &str,
    syron_address: Option<String>,
    txid: Option<String>,
    min_fee: u64
) -> Result<String, UpdateBalanceError> {
    // @dev 1. Set Bitcoin network
    let network =
        state::read_state(|s| (s.btc_network));
    let btc_network: BitcoinNetwork = match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    let fee_per_byte = select_fee_per_byte(btc_network, min_fee).await;

    let ecdsa_public_key = state::read_state(|s| s.ecdsa_public_key.clone()).expect("ECDSA public key not initialized");

    let sdb_subaccount = compute_subaccount(1, &ssi);
    
    let account = Account {
        owner: ic_cdk::id(),
        subaccount: Some(sdb_subaccount)
    };

    // @dev Fetch SDB's public key and UTXOs.
    let sdb_public_key = derive_ssi_public_key(&ecdsa_public_key, &account, &ssi).public_key;
    
    // Note that pagination may have to be used to get all UTXOs for the given address.
    // For the sake of simplicity, it is assumed here that the `utxo` field in the response
    // contains all UTXOs.
    let mut utxos: Vec<Utxo> =
        bitcoin_api::get_utxos(btc_network, sdb.clone())
        .await
        .utxos;

    // @dev Parse addresses
    let sdb_address = BitcoinAddress::parse(&sdb, network).unwrap();
    let dst_address = BitcoinAddress::parse(dst_address, network).unwrap();
   
    // @dev Build transaction
    let transaction = match syron_address {
        Some(address) => {
            let syron_address = BitcoinAddress::parse(&address, network).unwrap();
            
            // @dev The inscribe-transfer UTXO (SYRON BRC-20)
            let txid = txid.expect("No transaction ID provided for the SYRON BRC-20 inscribe-transfer UTXO.");

            let mut select_utxo: Option<Utxo> = None;
            for index in (0..utxos.len()).rev() {
                let utxo = &utxos[index];

                let txid_bytes = utxo.outpoint.txid.iter().rev().map(|n| *n as u8).collect::<Vec<u8>>();
                let txid_hex = hex::encode(txid_bytes);
                if txid_hex == txid {
                    select_utxo = Some(utxo.clone());
                    utxos.remove(index);
                }
            }

            let select_utxo = select_utxo.expect("No matching UTXO found!");

            // let utxos: Vec<ic_btc_interface::Utxo> =
            // get_utxos(network, &own_address, 1, CallSource::Client) // @review (mainnet) min confirmations
            // .await
            // .unwrap().utxos;

            // for utxo in &own_utxos {
            //     log!(
            //         P1,
            //         "Minter UTXO: {}",
            //         DisplayOutpoint(&utxo.outpoint)
            //     );
            // }
     
            // Unsigned transaction
            build_unsigned_transaction(
                &sdb_public_key,
                sdb_address,
                &utxos,
                dst_address,
                amount,
                fee_per_byte,
                syron_address,
                select_utxo
            ).await?
        },
        None => {
            build_unsigned_btc_transaction(
                true,
                &sdb_public_key,
                sdb_address,
                &utxos,
                dst_address,
                amount,
                fee_per_byte
            ).await?
        }
    };

    // @dev Sign the transaction
    let derivation_path: Vec<Vec<u8>> = get_ssi_derivation_path(&account, ssi).into_iter().map(|index| index.0).collect();
    let signed_transaction: SignedTransaction = sign_transaction_p2wpkh(
        &sdb_public_key,
        transaction.clone(),
        derivation_path,
    )
    .await.unwrap();

    let concatenated_result = format!(
        "Fee per byte: {} && Transaction ID: {}",
        fee_per_byte,
        transaction.txid().to_string(),
    );

    let signed_transaction_bytes = signed_transaction.serialize();
    match bitcoin_api::send_transaction(btc_network, signed_transaction_bytes).await {
        Ok(()) => Ok(concatenated_result),
        Err(err) => Err(err)
    }
}

pub(crate) async fn gas_p2wpkh(
    amount: u64,
    ssi: &str,
    btc_network: BitcoinNetwork,
    sdb: String,
    dst_address: &str,
    syron_address: &str
) -> u64 {
    // Get fee percentiles from previous transactions to estimate our own fee.
    let fee_percentiles = bitcoin_api::get_current_fee_percentiles(btc_network).await;

    // @dev Gas in satoshis per byte @review (signet)
    let fee_per_byte = if fee_percentiles.is_empty() {
        // There are no fee percentiles. This case can only happen on a regtest
        // network where there are no non-coinbase transactions. In this case,
        // we use a default of 5000 millisatoshis/byte (i.e. 5 satoshi/byte)
        10000
    } else {
        // Choose the 50th percentile for sending fees.
        fee_percentiles[50]
    };

    let ecdsa_public_key = state::read_state(|s| s.ecdsa_public_key.clone()).expect("ECDSA public key not initialized");

    let sdb_subaccount = compute_subaccount(1, &ssi);
    
    let account = Account {
        owner: ic_cdk::id(),
        subaccount: Some(sdb_subaccount)
    };

    // @dev Fetch SDB's public key and UTXOs.
    let sdb_public_key = derive_ssi_public_key(&ecdsa_public_key, &account, &ssi).public_key;
    
    let network =
        state::read_state(|s| (s.btc_network));

    print("Fetching UTXOs...");
    // Note that pagination may have to be used to get all UTXOs for the given address.
    // For the sake of simplicity, it is assumed here that the `utxo` field in the response
    // contains all UTXOs.
    let mut utxos: Vec<Utxo> =
        bitcoin_api::get_utxos(btc_network, sdb.clone())
        .await
        .utxos;

    // @dev The SUSD inscribe-transfer UTXO (dummy)
    let mut select_utxo: Option<Utxo> = None;

    // @dev Remove the UTXOs with a value less than 600 satoshis, which are probably inscriptions BUT select one of them
    for index in (0..utxos.len()).rev() {
        let utxo = &utxos[index];
        
        if utxo.value < 600 {
            select_utxo = Some(utxo.clone());
            utxos.remove(index);
        }
    }

    let select_utxo = select_utxo.expect("No matching UTXO found!");

    let sdb_address = BitcoinAddress::parse(&sdb, network).unwrap();
    let dst_address = BitcoinAddress::parse(&dst_address, network).unwrap();
    let syron_address = BitcoinAddress::parse(syron_address, network).unwrap();
    
    build_transaction_gas(
        &sdb_public_key,
        sdb_address,
        &utxos,
        dst_address,
        amount,
        fee_per_byte,
        syron_address,
        select_utxo
    ).await
}

pub(crate) async fn liquidate_p2wpkh(
    amount: u64,
    ssi: &str,
    sdb: String,
    dst_address: &str,
    min_fee: u64
) -> Result<[u8;32], UpdateBalanceError> {
    // @dev 1. Set Bitcoin network
    let network =
        state::read_state(|s| (s.btc_network));
    let btc_network: BitcoinNetwork = match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    let fee_per_byte = select_fee_per_byte(btc_network, min_fee).await;

    let ecdsa_public_key = state::read_state(|s| s.ecdsa_public_key.clone()).expect("ECDSA public key not initialized");

    let sdb_subaccount = compute_subaccount(1, &ssi);
    
    let account = Account {
        owner: ic_cdk::id(),
        subaccount: Some(sdb_subaccount)
    };

    // @dev Fetch SDB's public key and UTXOs.
    let sdb_public_key = derive_ssi_public_key(&ecdsa_public_key, &account, &ssi).public_key;

    // Note that pagination may have to be used to get all UTXOs for the given address.
    // For the sake of simplicity, it is assumed here that the `utxo` field in the response
    // contains all UTXOs.
    let mut utxos: Vec<Utxo> =
        bitcoin_api::get_utxos(btc_network, sdb.clone())
        .await
        .utxos;

    // @dev Remove the UTXOs with a value less than 600 satoshis, which are probably inscriptions.
    for index in (0..utxos.len()).rev() {
        let utxo = &utxos[index];

        if utxo.value < 600 {
            utxos.remove(index);
        }
    }

    let sdb_address = BitcoinAddress::parse(&sdb, network).unwrap();
    let dst_address = BitcoinAddress::parse(dst_address, network).unwrap();

    let transaction = build_unsigned_liquidation(
        &sdb_public_key,
        sdb_address,
        &utxos,
        dst_address,
        amount,
        fee_per_byte
    ).await;

    // Sign the transaction.
    let derivation_path: Vec<Vec<u8>> = get_ssi_derivation_path(&account, ssi).into_iter().map(|index| index.0).collect();

    let signed_transaction: SignedTransaction = sign_transaction_p2wpkh(
        &sdb_public_key,
        transaction,
        derivation_path,
    )
    .await.unwrap();

    let signed_transaction_bytes = signed_transaction.serialize();
    match bitcoin_api::send_transaction(btc_network, signed_transaction_bytes).await {
        Ok(()) => Ok(signed_transaction.wtxid()),
        Err(err) => Err(err)
    }
}

async fn build_unsigned_transaction(
    public_key: &[u8],
    address: BitcoinAddress,
    utxos: &[Utxo],
    dst_address: BitcoinAddress,
    amount: Satoshi,
    fee_per_byte: MillisatoshiPerByte,
    syron_address: BitcoinAddress,
    select_utxo: Utxo
) -> Result<UnsignedTransaction, UpdateBalanceError> {
    // We have a chicken-and-egg problem where we need to know the length
    // of the transaction in order to compute its proper fee, but we need
    // to know the proper fee in order to figure out the inputs needed for
    // the transaction.
    //
    // We solve this problem iteratively. We start with a fee of zero, build
    // and sign a transaction, see what its size is, and then update the fee,
    // rebuild the transaction, until the fee is set to the correct amount.
    print("Building transaction...");
    let mut total_fee = 0;
    loop {
        let transaction =
            build_unsigned_tx_with_fee(utxos, address.clone(), dst_address.clone(), amount, total_fee, syron_address.clone(), select_utxo.clone())
                .expect("Error building transaction");

        // Sign the transaction. In this case, we only care about the size
        // of the signed transaction, so we use a mock signer here for efficiency.
        let signed_transaction = sign_transaction_p2wpkh(
            public_key,
            transaction.clone(),
            vec![],           // mock derivation path
        )
        .await.unwrap();

        let signed_tx_bytes_len = signed_transaction.serialize().len() as u64;

        if (signed_tx_bytes_len * fee_per_byte) / 1000 == total_fee {
            ic_cdk::println!("Transaction built with total fee {:?}.", total_fee);
            return Ok(transaction);
        } else {
            total_fee = (signed_tx_bytes_len * fee_per_byte) / 1000;
        }
    }
}

async fn build_transaction_gas(
    public_key: &[u8],
    address: BitcoinAddress,
    utxos: &[Utxo],
    dst_address: BitcoinAddress,
    amount: Satoshi,
    fee_per_byte: MillisatoshiPerByte,
    syron_address: BitcoinAddress,
    select_utxo: Utxo
) -> u64 {
    let mut total_fee = 0;
    loop {
        match build_unsigned_tx_with_fee(utxos, address.clone(), dst_address.clone(), amount, total_fee, syron_address.clone(), select_utxo.clone()) {
            Ok(transaction) => {
                // Sign the transaction. In this case, we only care about the size
                // of the signed transaction, so we use a mock signer here for efficiency.
                let signed_transaction = sign_transaction_p2wpkh(
                    public_key,
                    transaction.clone(),
                    vec![],           // mock derivation path
                )
                .await.unwrap();

                let signed_tx_bytes_len = signed_transaction.serialize().len() as u64;

                if (signed_tx_bytes_len * fee_per_byte) / 1000 == total_fee {
                    return 0; // @dev no extra gas required
                } else {
                    total_fee = (signed_tx_bytes_len * fee_per_byte) / 1000;
                }
            },
            Err (error) => {
                // Extract the required additional balance from the error message
                if let Some(captures) = regex::Regex::new(r"Please deposit at least (\d+) sats into your SDB.")
                .unwrap()
                .captures(&error)
                {
                    if let Some(matched) = captures.get(1) {
                        let gas = matched.as_str().parse().unwrap();
                        return gas;
                    }
                }
            }
        }
    }
}

async fn build_unsigned_liquidation(
    public_key: &[u8],
    address: BitcoinAddress,
    utxos: &[Utxo],
    dst_address: BitcoinAddress,
    amount: Satoshi,
    fee_per_byte: MillisatoshiPerByte
) -> UnsignedTransaction {
    // We have a chicken-and-egg problem where we need to know the length
    // of the transaction in order to compute its proper fee, but we need
    // to know the proper fee in order to figure out the inputs needed for
    // the transaction.
    //
    // We solve this problem iteratively. We start with a fee of zero, build
    // and sign a transaction, see what its size is, and then update the fee,
    // rebuild the transaction, until the fee is set to the correct amount.
    print("Building transaction...");
    let mut total_fee = 0;
    loop {
        let transaction =
            build_unsigned_liquidation_with_fee(utxos, address.clone(), dst_address.clone(), amount, total_fee)
                .expect("Error building transaction");

        // Sign the transaction. In this case, we only care about the size
        // of the signed transaction, so we use a mock signer here for efficiency.
        let signed_transaction = sign_transaction_p2wpkh(
            public_key,
            transaction.clone(),
            vec![],           // mock derivation path
        )
        .await.unwrap();

        let signed_tx_bytes_len = signed_transaction.serialize().len() as u64;

        if (signed_tx_bytes_len * fee_per_byte) / 1000 == total_fee {
            ic_cdk::println!("Transaction built with total fee {:?}.", total_fee);
            return transaction;
        } else {
            total_fee = (signed_tx_bytes_len * fee_per_byte) / 1000;
        }
    }
}

fn vec_to_txid(vec: Vec<u8>) -> ic_ckbtc_minter_tyron::tx::Txid {
    let bytes: [u8; 32] = std::convert::TryInto::try_into(vec).expect("Can't convert to [u8; 32]");
    bytes.into()
}

fn build_unsigned_tx_with_fee(
    utxos: &[Utxo],
    address: BitcoinAddress,
    dst_address: BitcoinAddress,
    mut amount: u64,
    fee: u64,
    syron_address: BitcoinAddress,
    select_utxo: Utxo
) -> Result<UnsignedTransaction, String> {
    // Assume that any amount below this threshold is dust.
    //@review (mainnet)
    const DUST_THRESHOLD: u64 = 0;

    // Select which UTXOs to spend. We naively spend the oldest available UTXOs,
    // even if they were previously spent in a transaction. This isn't a
    // problem as long as at most one transaction is created per block and
    // we're using min_confirmations of 1.
    let mut utxos_to_spend = vec![];
    let mut utxos_balance = 0;
    for utxo in utxos.iter().rev() {
        utxos_balance += utxo.value;
        utxos_to_spend.push(utxo);
        if utxos_balance >= amount + fee {
            // We have enough inputs to cover the amount we want to spend.
            break;
        }
    }

    // @dev The inscribe-transfer UTXO is sent to the minter, thus its balance must not be considered (it is "locked").
    utxos_balance -= select_utxo.value;

    if utxos_balance < fee {
        return Err(format!(
            "Insufficient unlocked balance ({} sats) - Trying to transfer {} sats with a fee of {} sats. Please deposit at least {} sats into your SDB in order to withdraw {} sats.", // @review suggested deposit amount 
            utxos_balance, amount, fee, fee + amount - utxos_balance, amount // address @review (format) since now it prints P2wpkhV0([8, 102, 59, 71, 220, 132, 106, 200, 211, 158, 166, 47, 226, 90, 232, 191, 111, 237, 157, 197])
        ));
    } else {
        amount = utxos_balance - fee;
    }
    let mut inputs: Vec<UnsignedInput> = vec![];

    // @dev Send SUSD back to the minter
    inputs.push(UnsignedInput {
        previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
            txid: vec_to_txid(select_utxo.outpoint.txid),
            vout: select_utxo.outpoint.vout,
        },
        value: select_utxo.value,
        sequence: 0xffffffff,
    });

    let mut utxos_for_fee: Vec<UnsignedInput> = utxos_to_spend
        .into_iter()
        .map(|utxo| UnsignedInput {
            previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
                txid: vec_to_txid(utxo.outpoint.txid.clone()),
                vout: utxo.outpoint.vout,
            },
            value: utxo.value,
            sequence: 0xffffffff,
        })
        .collect();

    inputs.append(&mut utxos_for_fee);
    ic_cdk::println!("UTXO Inputs: {:?}", inputs);

    let mut outputs: Vec<ic_ckbtc_minter_tyron::tx::TxOut> = vec![
    ic_ckbtc_minter_tyron::tx::TxOut {
        address: syron_address,
        value: select_utxo.value,
    }];
    
    outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
        address: dst_address,
        value: amount, // balance - inscribe-transfer - gas fee
    });

    let remaining_amount = utxos_balance - amount - fee;
    if remaining_amount > DUST_THRESHOLD {
        outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
            address,
            value: remaining_amount,
        });
    }
    ic_cdk::println!("UTXO Outputs: {:?}", outputs);

    Ok(UnsignedTransaction {
        inputs,
        outputs,
        lock_time: 0,
    })
}

fn build_unsigned_liquidation_with_fee(
    utxos: &[Utxo],
    address: BitcoinAddress,
    dst_address: BitcoinAddress,
    amount: u64,
    fee: u64
) -> Result<UnsignedTransaction, String> {
    // Assume that any amount below this threshold is dust.
    //@review (mainnet)
    const DUST_THRESHOLD: u64 = 0;

    // Select which UTXOs to spend. We naively spend the oldest available UTXOs,
    // even if they were previously spent in a transaction. This isn't a
    // problem as long as at most one transaction is created per block and
    // we're using min_confirmations of 1.
    let mut utxos_to_spend = vec![];
    let mut utxos_balance = 0;
    for utxo in utxos.iter().rev() {
        utxos_balance += utxo.value;
        utxos_to_spend.push(utxo);
        if utxos_balance >= amount + fee {
            // We have enough inputs to cover the amount we want to spend.
            break;
        }
    }

    if utxos_balance < amount + fee {
        return Err(format!(
            "Insufficient balance ({} sats) - Trying to transfer {} sats with a fee of {} sats. Please deposit at least {} sats into your SDB.",
            utxos_balance, amount, fee, fee + amount - utxos_balance, // address @review (format) since now it prints P2wpkhV0([8, 102, 59, 71, 220, 132, 106, 200, 211, 158, 166, 47, 226, 90, 232, 191, 111, 237, 157, 197])
        ));
    }

    let inputs: Vec<UnsignedInput> = utxos_to_spend
        .into_iter()
        .map(|utxo| UnsignedInput {
            previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
                txid: vec_to_txid(utxo.outpoint.txid.clone()),
                vout: utxo.outpoint.vout,
            },
            value: utxo.value,
            sequence: 0xffffffff,
        })
        .collect();

    let mut outputs: Vec<ic_ckbtc_minter_tyron::tx::TxOut> = vec![ic_ckbtc_minter_tyron::tx::TxOut {
        address: dst_address,
        value: amount,
    }];

    let remaining_amount = utxos_balance - amount - fee;

    if remaining_amount > DUST_THRESHOLD {
        outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
            address,
            value: remaining_amount,
        });
    }

    Ok(UnsignedTransaction {
        inputs,
        outputs,
        lock_time: 0,
    })
}

async fn build_unsigned_mint(
    own_public_key: &[u8],
    own_address: BitcoinAddress,
    select_utxo: Utxo,
    // fee_utxos: &[ic_btc_interface::Utxo],
    fee_utxos: &[Utxo],
    dst_address: BitcoinAddress,
    fee_per_byte: MillisatoshiPerByte,
) -> Result<UnsignedTransaction, UpdateBalanceError>  {
    // We have a chicken-and-egg problem where we need to know the length
    // of the transaction in order to compute its proper fee, but we need
    // to know the proper fee in order to figure out the UTXO inputs needed for
    // the transaction.
    //
    // We solve this problem iteratively. We start with a fee of zero, build
    // and sign a transaction, see what its size is, and then update the fee,
    // rebuild the transaction, until the fee is set to the correct amount.
    print("Building transaction...");
    let mut total_fee = 0;
    loop {
        let transaction =
            build_unsigned_mint_with_fee(select_utxo.clone(), fee_utxos, own_address.clone(), dst_address.clone(), total_fee)?;

        // Sign the transaction. In this case, we only care about the size
        // of the signed transaction, so we use a mock signer here for efficiency.
        let signed_transaction = sign_transaction_p2wpkh(
            own_public_key,
            transaction.clone(),
            vec![],           // mock derivation path
        )
        .await.unwrap();

        let signed_tx_bytes_len = signed_transaction.serialize().len() as u64;

        if (signed_tx_bytes_len * fee_per_byte) / 1000 == total_fee {
            ic_cdk::println!("Transaction built with total fee {:?}.", total_fee);
            return Ok(transaction);
        } else {
            total_fee = (signed_tx_bytes_len * fee_per_byte) / 1000;
        }
    }
}

fn build_unsigned_mint_with_fee(
    select_utxo: Utxo,
    // fee_utxos: &[ic_btc_interface::Utxo],
    fee_utxos: &[Utxo],
    own_address: BitcoinAddress,
    dst_address: BitcoinAddress,
    fee: u64,
) -> Result<UnsignedTransaction, UpdateBalanceError> {
    // Select which UTXOs to spend. We naively spend the oldest available UTXOs,
    // even if they were previously spent in a transaction. This isn't a
    // problem as long as at most one transaction is created per block and
    // we're using min_confirmations of 1.
    let mut utxos_to_spend = vec![];
    let mut to_spend_in_fees = 0;
    for utxo in fee_utxos.iter().rev() {
        to_spend_in_fees += utxo.value;
        utxos_to_spend.push(utxo);
        if to_spend_in_fees >= fee {
            // We have enough inputs to cover the amount we want to spend.
            break;
        }
    }

    if to_spend_in_fees < fee {
        return Err(UpdateBalanceError::GenericError{
            error_code: 5001,
            error_message: format!(
                "Insufficient balance: {}, to cover fee of {}",
                to_spend_in_fees, fee
            )
        });
    }

    let mut inputs: Vec<UnsignedInput> = vec![];

    inputs.push(UnsignedInput {
        previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
            txid: vec_to_txid(select_utxo.outpoint.txid),
            vout: select_utxo.outpoint.vout,
        },
        value: select_utxo.value,
        sequence: 0xffffffff,
    });

    let mut utxos_for_fee: Vec<UnsignedInput> = utxos_to_spend
        .into_iter()
        .map(|utxo| UnsignedInput {
            previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
                // txid: utxo.outpoint.txid,
                txid: vec_to_txid(utxo.outpoint.txid.clone()),
                vout: utxo.outpoint.vout,
            },
            value: utxo.value,
            sequence: 0xffffffff,
        })
        .collect();

    inputs.append(&mut utxos_for_fee);
    ic_cdk::println!("UTXO Inputs: {:?}", inputs);

    let mut outputs: Vec<ic_ckbtc_minter_tyron::tx::TxOut> = vec![ic_ckbtc_minter_tyron::tx::TxOut {
        address: dst_address,
        value: select_utxo.value,
    }];
    
    let remaining_amount = to_spend_in_fees - fee;
    ic_cdk::println!("Remaining amount for minter: {:?} sats", remaining_amount);

    outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
        address: own_address,
        value: remaining_amount,
    });
    ic_cdk::println!("UTXO Outputs: {:?}", outputs);
    
    Ok(UnsignedTransaction {
        inputs,
        outputs,
        lock_time: 0,
    })
}

fn convert_to_bytebufs(data: Vec<Vec<u8>>) -> Vec<ByteBuf> {
    data.into_iter()
        .map(|inner| ByteBuf::from(inner))
        .collect()
}

/// `own_address` is a P2WPKH address.
async fn sign_transaction_p2wpkh(
    own_public_key: &[u8],
    unsigned_tx: UnsignedTransaction,
    derivation_path: Vec<Vec<u8>>
) -> Result<SignedTransaction, CallError> {
    // Verify that our own address is P2WPKH. @review (test)
    // assert_eq!(
    //     own_address.address_type(),
    //     Some(AddressType::P2wpkh),
    //     "This function supports signing p2wpkh addresses only."
    // );
    let mut signed_inputs = Vec::with_capacity(unsigned_tx.inputs.len());
    
    let sighasher = tx::TxSigHasher::new(&unsigned_tx);

    let path = convert_to_bytebufs(derivation_path);
    
    let key_name = state::read_state(|s| s.ecdsa_key_name.clone());

    for input in &unsigned_tx.inputs {
        let outpoint = &input.previous_output;

        let pubkey = ByteBuf::from(own_public_key);
        let pkhash = tx::hash160(&pubkey);

        let sighash = sighasher.sighash(&input, &pkhash);

        let sec1_signature =
            sign_with_ecdsa(key_name.clone(), DerivationPath::new(path.clone()), sighash)
            .await?;

        signed_inputs.push(SignedInput {
            signature: EncodedSignature::from_sec1(&sec1_signature),
            pubkey,
            previous_output: outpoint.clone(),
            sequence: input.sequence,
        });
    }

    Ok(SignedTransaction {
        inputs: signed_inputs,
        outputs: unsigned_tx.outputs,
        lock_time: unsigned_tx.lock_time,
    })
}

/// @dev v3
pub(crate) async fn btc_p2wpkh(
    dao_addr: Vec<BitcoinAddress>,
    dst_address: BitcoinAddress,
    amount: u64,
    fee: u64    
) -> Result<Vec<String>, UpdateBalanceError> {
    // @dev Set Bitcoin network
    let network =
        state::read_state(|s| (s.btc_network));
    let btc_network: BitcoinNetwork = match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    // Set the gas fee per byte
    let fee_per_byte = select_fee_per_byte(btc_network, fee).await;
    
    // @dev Fetch DAO data
    // The minter address is the SSI
    // The Treasury address is the minter's Safety Deposit Box
    let ssi_addr = &dao_addr[0];
    let ssi = ssi_addr.display(network); 
    let treasury_addr = &dao_addr[1];
    let treasury_address = treasury_addr.display(network);

    ic_cdk::println!("Treasury address: {:?}", treasury_address);

    // SDB subaccount & account
    let subaccount = compute_subaccount(1, &ssi);
    let account = Account {
        owner: ic_cdk::id(),
        subaccount: Some(subaccount)
    };

    // SDB public key
    let ecdsa_public_key = state::read_state(|s| s.ecdsa_public_key.clone()).expect("ECDSA public key not initialized");
    let public_key = derive_ssi_public_key(&ecdsa_public_key, &account, &ssi).public_key;
    
    // Fetch UTXOs
    let treasury_utxos: Vec<Utxo> =
        bitcoin_api::get_utxos(btc_network, treasury_address.clone())
        .await
        .utxos;

    // @dev Build transaction
    // Build unsigned transaction
    let transaction = build_unsigned_btc_transaction(
        false,
        &public_key,
        treasury_addr.clone(),
        &treasury_utxos,
        dst_address,
        amount,
        fee_per_byte
    ).await?;

    // Sign the transaction with SSI derivation path
    let derivation_path: Vec<Vec<u8>> = get_ssi_derivation_path(&account, &ssi).into_iter().map(|index| index.0).collect();
  
    let signed_transaction: SignedTransaction = sign_transaction_p2wpkh(
        &public_key,
        transaction.clone(),
        derivation_path,
    )
    .await.map_err(|err| UpdateBalanceError::CallError{method: err.method().to_string(), reason: Reason::to_string(err.reason())})?;

    // Send the transaction & print result
    let signed_transaction_bytes = signed_transaction.serialize();

    let result: Vec<String> = vec![
        format!("transaction_id: {}", transaction.txid().to_string()),
        format!("given_fee: {}", fee_per_byte),
    ];
    
    match bitcoin_api::send_transaction(btc_network, signed_transaction_bytes).await {
        Ok(()) => Ok(result),
        Err(err) => Err(err)
    }
}

async fn build_unsigned_btc_transaction(
    is_redeem: bool,
    public_key: &[u8],
    address: BitcoinAddress,
    utxos: &[Utxo],
    dst_address: BitcoinAddress,
    amount: Satoshi,
    fee_per_byte: MillisatoshiPerByte
) -> Result<UnsignedTransaction, UpdateBalanceError> {
    // We have a chicken-and-egg problem where we need to know the length
    // of the transaction in order to compute its proper fee, but we need
    // to know the proper fee in order to figure out the inputs needed for
    // the transaction.
    //
    // We solve this problem iteratively. We start with a fee of zero, build
    // and sign a transaction, see what its size is, and then update the fee,
    // rebuild the transaction, until the fee is set to the correct amount.
    
    let mut total_fee = 0;
    loop {
        let transaction =
            build_unsigned_btc_tx_with_fee(is_redeem, utxos, address.clone(), dst_address.clone(), amount, total_fee)
                .expect("Error building transaction");

        // Sign the transaction. In this case, we only care about the size
        // of the signed transaction, so we use a mock signer here for efficiency.
        let signed_transaction = sign_transaction_p2wpkh(
            public_key,
            transaction.clone(),
            vec![],           // mock derivation path
        )
        .await.unwrap();

        let mut signed_tx_bytes_len = signed_transaction.serialize().len() as u64;
        ic_cdk::println!("Signed transaction size: {:?}", signed_tx_bytes_len);
        
        signed_tx_bytes_len = (signed_tx_bytes_len as f64 * 0.7) as u64;
        if (signed_tx_bytes_len * fee_per_byte) / 1000 == total_fee {
            ic_cdk::println!("Transaction built with total fee {:?}.", total_fee);
            return Ok(transaction);
        } else {
            total_fee = (signed_tx_bytes_len * fee_per_byte) / 1000;
        }
    }
}

fn build_unsigned_btc_tx_with_fee(
    is_redeem: bool,
    utxos: &[Utxo],
    address: BitcoinAddress,
    dst_address: BitcoinAddress,
    amount: u64,
    fee: u64,
) -> Result<UnsignedTransaction, String> {
    // Assume that any amount below this threshold is dust.
    // @review (mainnet)
    const DUST_THRESHOLD: u64 = 0;

    if amount < fee {
        return Err(format!(
            "Insufficient amount ({} sats) - even lower than fee ({} sats)",
            amount, fee
        ));
    }

    // Select which UTXOs to spend. We naively spend the oldest available UTXOs,
    // even if they were previously spent in a transaction. This isn't a
    // problem as long as at most one transaction is created per block and
    // we're using min_confirmations of 1.
    let mut utxos_to_spend = vec![];
    let mut utxos_balance = 0;
    for utxo in utxos.iter().rev() {
        utxos_balance += utxo.value;
        utxos_to_spend.push(utxo);
        if utxos_balance >= amount {
            // We have enough inputs to cover the amount we want to spend.
            break;
        }
    }

    if utxos_balance < amount {
        return Err(format!(
            "Insufficient balance ({} sats) - Trying to transfer {} sats with a fee of {} sats",
            utxos_balance, amount, fee
            ));
    }

    let withdraw_amount = if is_redeem {
        // @dev Redemptions always withdraw the entire collateral balance
        utxos_balance - fee
    } else {
        // @dao swap
        amount - fee - 100 // @governance swap fee
    };

    if withdraw_amount < 200 {
        return Err(format!(
            "Insufficient withdraw amount result ({} sats) - min btc acquired shall be 200 sats",
            withdraw_amount
        ));
    }
    
    // @dev Transaction UTXOs
    let mut inputs: Vec<UnsignedInput> = vec![];

    let mut comsume_utxos: Vec<UnsignedInput> = utxos_to_spend
        .into_iter()
        .map(|utxo| UnsignedInput {
            previous_output: ic_ckbtc_minter_tyron::tx::OutPoint {
                txid: vec_to_txid(utxo.outpoint.txid.clone()),
                vout: utxo.outpoint.vout,
            },
            value: utxo.value,
            sequence: 0xffffffff,
        })
        .collect();

    inputs.append(&mut comsume_utxos);
    ic_cdk::println!("UTXO Inputs: {:?}", inputs);

    let mut outputs: Vec<ic_ckbtc_minter_tyron::tx::TxOut> = vec![];
    
    outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
        address: dst_address,
        value: withdraw_amount,
    });

    let remaining_amount = utxos_balance - amount;

    if remaining_amount > DUST_THRESHOLD {
        outputs.push(ic_ckbtc_minter_tyron::tx::TxOut {
            address,
            value: remaining_amount,
        });
    }
    ic_cdk::println!("UTXO Outputs: {:?}", outputs);

    Ok(UnsignedTransaction {
        inputs,
        outputs,
        lock_time: 0,
    })
}

async fn select_fee_per_byte(
    btc_network: BitcoinNetwork,
    min_fee: u64
) -> u64 {
    // Get fee percentiles from previous transactions to estimate our current gas fee
    let fee_percentiles = bitcoin_api::get_current_fee_percentiles(btc_network).await;

    // Select gas fee in satoshis per byte 
    let  fee_per_byte = if fee_percentiles.is_empty() {
        // If there are no fee percentiles (this case can only happen on a regtest
        // network where there are no non-coinbase transactions),
        // we use a default of 5000 millisatoshis/byte (i.e. 5 satoshi/byte)
        5000
    } else {
        // Choose the 50th percentile for sending fees.
        fee_percentiles[50]
    };
    ic_cdk::println!("Fee per byte: {:?}", fee_per_byte);
    // Choose fee_per_byte as the given min_fee except if min_fee > fee_per_byte
    if min_fee > fee_per_byte {
        return fee_per_byte
    } else {
        return min_fee
    }
    // std::cmp::max(min_fee, fee_per_byte)
}

pub(crate) async fn fetch_bitcoin_network() -> BitcoinNetwork {
    // @dev Read Network
    let network =
        state::read_state(|s| (s.btc_network));
    let btc_network: BitcoinNetwork = match network {
        Network::Mainnet => BitcoinNetwork::Mainnet,
        _ => BitcoinNetwork::Testnet,
    };
    return btc_network
}
