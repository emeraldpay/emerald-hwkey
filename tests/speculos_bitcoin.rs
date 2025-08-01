// Copyright 2025 EmeraldPay, Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused_imports)]
#![allow(dead_code)]
#![cfg(all(integration_test, feature = "speculos"))]

#[macro_use]
extern crate lazy_static;

mod common;

use hdpath::StandardHDPath;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use emerald_hwkey::ledger::app::bitcoin::{AddressResponse, GetAddressOpts, AppVersion, BitcoinApp, BitcoinApps, UnsignedInput, SignTx};
use std::convert::TryFrom;
use bitcoin::{
    Address,
    Network,
    OutPoint,
    Transaction,
    Txid,
    TxIn,
    TxOut,
    consensus::Encodable,
    NetworkKind,
    Amount,
    absolute::LockTime,
    Sequence,
    address::NetworkChecked
};
use std::str::FromStr;
use std::sync::{Arc, mpsc, Mutex};
use std::thread;
use std::thread::spawn;
use std::time::Duration;
use emerald_hwkey::ledger::app::LedgerApp;
use emerald_hwkey::ledger::connect::speculos_api::{Speculos, Button};
use emerald_hwkey::ledger::connect::{LedgerSpeculosKey, LedgerKey};
use testcontainers::runners::AsyncRunner;
use testcontainers::core::ContainerPort;
use common::speculos_container::{SpeculosConfig, start_speculos_client};

fn config_nanos_16() -> SpeculosConfig {
    SpeculosConfig::bitcoin()
        .with_nano_s()
        .with_sdk_v1()
        .with_app("apps/nanos#btc#1.6#6bd0a5f8.elf")
}

fn config_nanos_21() -> SpeculosConfig {
    SpeculosConfig::bitcoin()
        .with_nano_s()
        .with_sdk_v2()
        .with_app("apps/nanos#btc#2.1#1c8db8da.elf")
}

fn config_nanox_20() -> SpeculosConfig {
    SpeculosConfig::bitcoin()
        .with_nano_x()
        .with_sdk("2.0.2")
        .with_app("apps/nanox#btc#2.0.2#1c8db8da.elf")
}


#[tokio::test]
pub async fn is_app_open_nano_s_sdk_v1() {
    is_app_open(
        config_nanos_16()
    ).await
}

#[tokio::test]
pub async fn is_app_open_nano_s_sdk_v2() {
    is_app_open(
        config_nanos_21()
    ).await
}

#[tokio::test]
pub async fn is_app_open_nano_x_sdk_v2() {
    is_app_open(
        config_nanox_20()
    ).await
}

async fn is_app_open(config: SpeculosConfig) {
    common::init();
    let (_speculos, manager, _container) = start_speculos_client(config).await.unwrap();
    let app = manager.access::<BitcoinApp>().unwrap();
    let open = app.is_open();
    assert_eq!(Some(BitcoinApps::Mainnet), open);
}

#[tokio::test]
pub async fn get_address_nano_s_sdk_v1() {
    get_address(
        config_nanos_16()
    ).await
}

#[tokio::test]
pub async fn get_address_nano_s_sdk_v2() {
    get_address(
        config_nanos_21()
    ).await
}

#[tokio::test]
pub async fn get_address_nano_x_sdk_v2() {
    get_address(
        config_nanox_20()
    ).await
}

async fn get_address(config: SpeculosConfig) {
    let (_speculos, manager, _container) = start_speculos_client(config).await.unwrap();
    let app = manager.access::<BitcoinApp>().unwrap();

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qqtl9jlrwcr3fsfcjj2du7pu6fcgaxl5dsw2vyg").unwrap().require_network(Network::Bitcoin).unwrap());
    assert_eq!(hex::encode(act.pubkey.inner.serialize()), "031869567d5e88d988ff7baf6827983f89530ddd79dbaeadaa6ec538a8f03dea8b");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qfw40lw34279da7c5vwpe0n9w2pxuqrw2wsyfyh").unwrap().require_network(Network::Bitcoin).unwrap());
    assert_eq!(hex::encode(act.pubkey.inner.serialize()), "0239daaa23f25002a17f40adac8df385dd5701e5df708c78ec0b7c28a2bfc9412f");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qxqfdqh8nz2ledrmnemhwlwcly05w0gzfutqsah").unwrap().require_network(Network::Bitcoin).unwrap());
    assert_eq!(hex::encode(act.pubkey.inner.serialize()), "02e1c5b650702d3099b397b423935c9442b30c78235c4fa888a1db244b2bc716a5");
}

#[tokio::test]
pub async fn get_address_confirmed_nano_s_sdk_v1() {
    get_address_confirmed(
        config_nanos_16(), 3
    ).await
}

#[tokio::test]
pub async fn get_address_confirmed_nano_s_sdk_v2() {
    get_address_confirmed(
        config_nanos_21(), 3
    ).await
}

#[tokio::test]
pub async fn get_address_confirmed_nano_x_sdk_v2() {
    get_address_confirmed(
        config_nanox_20(), 1
    ).await
}

async fn get_address_confirmed(config: SpeculosConfig, pages: usize) {
    let (speculos, manager, _container) = start_speculos_client(config).await.unwrap();
    let (tx, rx) = mpsc::channel();
    spawn(move || {
        let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
        let app = manager.access::<BitcoinApp>().unwrap();
        let act = app.get_address(&hdpath, GetAddressOpts::confirm()).expect("Failed to get address");
        tx.send(act).unwrap();
    });
    // give time for the thread above to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    for _ in 0..pages {
        // press right to show the next page
        speculos.press(Button::Right).unwrap();
    }
    // on the next page we have a confirmation button
    speculos.press(Button::Both).unwrap();
    let act = rx.recv().unwrap();

    assert_eq!(act.address, Address::from_str("bc1qqtl9jlrwcr3fsfcjj2du7pu6fcgaxl5dsw2vyg").unwrap().require_network(Network::Bitcoin).unwrap());
    assert_eq!(hex::encode(act.pubkey.inner.serialize()), "031869567d5e88d988ff7baf6827983f89530ddd79dbaeadaa6ec538a8f03dea8b");
}

#[tokio::test]
pub async fn sign_tx_testnet_1() {
    common::init();
    let (speculos, manager, _container) = start_speculos_client(SpeculosConfig::bitcoin_test()).await.unwrap();

    let (channel_tx, channel_rx) = mpsc::channel();
    spawn(move || {
        println!("Preparing to sign transaction");
        let from_amount = 4567800;
        let to_amount = from_amount - 123;

        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid::from_str("41217d32e29b67d01692eed0ca776ea24a9f03299dfc46dde1bf14d3918e5275").unwrap(), 0),
                    sequence: Sequence(0xfffffffd),
                    ..TxIn::default()
                }
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(to_amount), // = 4567677
                    script_pubkey: Address::from_str("tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0").unwrap().assume_checked().script_pubkey(),
                }
            ],
        };

        println!("Sign tx {}", hex::encode(bitcoin::consensus::serialize(&tx)));
        let app = manager.access::<BitcoinApp>().unwrap();
        let signed = app.sign_tx(&mut tx, &SignTx {
            inputs: vec![
                UnsignedInput {
                    index: 0,
                    amount: from_amount,
                    hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                }
            ],
            network: NetworkKind::Test,
        });
        channel_tx.send(signed.map(|_| tx)).unwrap();
    });
    // give time for the thread above to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // first confirm outputs
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    // then confirm transaction itself
    speculos.press(Button::Both).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Right).unwrap();
    speculos.press(Button::Both).unwrap();

    let tx = channel_rx.recv().unwrap();

    if tx.is_err() {
        panic!("Error signing transaction: {:?}", tx.err());
    }

    let tx = tx.unwrap();
    assert_eq!(
        hex::encode(bitcoin::consensus::serialize(&tx)),
        "0200000000010175528e91d314bfe1dd46fc9d29039f4aa26e77cad0ee9216d0679be2327d21410000000000fdffffff017db245000000000016001441446f32764c0e4e931bd69c2a2fabd34a6515c30248304502210098ffbc2e72bdb901f214473ecc58c4ccccc00510d839831e2950a729a3f4e73102202e83b8b1bf88157e7e5caae77814242997f3504bcde9b55ef3a7744b3c073c860121027cb75d34b005c4eb9f62bbf2c457d7638e813e757efcec8fa68677d950b6366200000000"
    );
}