#![allow(unused_imports)]
#![allow(dead_code)]
#![cfg(all(integration_test, test_ethereum, feature = "speculos"))]


use std::convert::TryFrom;
use std::sync::{Arc, mpsc, Mutex};
use std::thread;
use std::thread::spawn;
use std::time::Duration;
use rand::prelude::*;
use rand::seq::SliceRandom;
use rand::thread_rng;
use hdpath::StandardHDPath;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use emerald_hwkey::ledger::app::ethereum::EthereumApp;
use emerald_hwkey::ledger::connect::LedgerKey;
use emerald_hwkey::ledger::connect::speculos_api::{Button, Speculos};
use emerald_hwkey::ledger::connect::LedgerSpeculosKey;

#[test]
pub fn get_address() {
    let mut manager = LedgerSpeculosKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<EthereumApp>().unwrap();

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D");
    assert_eq!(hex::encode(act.pubkey.serialize()), "02ef5b152e3f15eb0c50c9916161c2309e54bd87b9adce722d69716bcdef85f547");

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/1").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0xd692Cb1346262F584D17B4B470954501f6715a82");
    assert_eq!(hex::encode(act.pubkey.serialize()), "03072993d175eea6ef5df9f1370c834e1321de0ad90255af580fda11a016c59a14");

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/2").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0xfeb0594A0561d0DF76EA8b2F52271538e6704f75");
    assert_eq!(hex::encode(act.pubkey.serialize()), "026d28a418c395c221c46d3e308d612c2d13cc5464d5eb7a02e1d142ed73fae3fb");

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/3").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0x5c886862AAbA7e342c8708190c42C14BD63e9058");
    assert_eq!(hex::encode(act.pubkey.serialize()), "034fead5f71d6a12d622e047f5b51d5b67935383a2cab014f020de37bec7de2442");

    let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/4").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0x766aedBf5FC4366Fe48D49604CAE12Ba11630A60");
    assert_eq!(hex::encode(act.pubkey.serialize()), "026f3b2877a3ddc326635d95f848631ee19e9d1fdbe6531f913f3b309fde604a31");


    let hdpath = StandardHDPath::try_from("m/44'/60'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0x204e73c731f06cF38C2486A768c579aC3fa412ba");
    assert_eq!(hex::encode(act.pubkey.serialize()), "0378cd117abe05a0c33e79cac3b2014ac30a65f959abf72b55f5bc8265bac4d0f0");

    let hdpath = StandardHDPath::try_from("m/44'/60'/1'/1/1").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, false).expect("Failed to get address");
    assert_eq!(act.address, "0xF249865B00b342d9B888b6D01f4d937B07828506");
    assert_eq!(hex::encode(act.pubkey.serialize()), "039120c9b52001f02f49888e7d6fbee1851a1b9e4378951a4b998253d958b289e9");
}

#[test]
pub fn get_address_parallel() {
    let addresses: Vec<(StandardHDPath, String)> = vec![
        ("m/44'/60'/0'/0/0", "0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D"),
        ("m/44'/60'/0'/0/1", "0xd692Cb1346262F584D17B4B470954501f6715a82"),
        ("m/44'/60'/0'/0/2", "0xfeb0594A0561d0DF76EA8b2F52271538e6704f75"),
        ("m/44'/60'/0'/0/3", "0x5c886862AAbA7e342c8708190c42C14BD63e9058"),
        ("m/44'/60'/0'/0/4", "0x766aedBf5FC4366Fe48D49604CAE12Ba11630A60"),
        ("m/44'/60'/0'/0/5", "0xbC2F9a0F57d2EDD630f2327C5E0caBff565c6B13"),
        ("m/44'/60'/0'/0/6", "0xF0eb55adF53795257118Af626206dAb7C43F8b04"),
        ("m/44'/60'/0'/0/7", "0x2de8e81E02154D954547322e412e3A2b2eE96C82"),
        ("m/44'/60'/0'/0/8", "0x014a648258C68b02980EF7a610E9468DAf14aBC9"),
        ("m/44'/60'/0'/0/9", "0xe0EA7FbA9Dc2d1901529CA45d5c2daD908F408E2"),
    ]
        .iter()
        .map(|p| (StandardHDPath::try_from(p.0).unwrap(), p.1.to_string() ))
        .collect();

    let mut threads = vec![];

    let mut manager = LedgerSpeculosKey::new().unwrap();
    manager.connect().expect("Not connected");
    manager.access::<EthereumApp>().unwrap();

    let manager = Arc::new(manager);
    let mut rnd = rand::thread_rng();

    for _ in 0..10 {
        let mut addresses = addresses.clone();
        addresses.shuffle(&mut rnd);
        let manager = manager.clone();
        threads.push(
            thread::spawn( move || {
                let mut rnd = rand::thread_rng();
                for p in addresses {
                    let hdpath = p.0;
                    let address = p.1;

                    let jitter = rnd.gen_range(1..5);
                    thread::sleep(Duration::from_millis(jitter));
                    let current = manager.access::<EthereumApp>().unwrap();
                    let act = current.get_address(&hdpath, false).unwrap();

                    println!("address {}: {} >=< {}", hdpath.to_string(), address, act.address);
                    assert_eq!(act.address, *address);
                }
            })
        );
    }

    for thread in threads {
        thread.join().unwrap()
    }
}

#[test]
pub fn sign_tx() {
    // send 1 ETH to 0x78296F1058dD49C5D6500855F59094F0a2876397 paying 20gwei for gas and nonce 3

    let (channel_tx, channel_rx) = mpsc::channel();
    let mut manager = LedgerSpeculosKey::new().unwrap();
    manager.connect().expect("Not connected");
    let speculos = Speculos::create_env();

    spawn(move || {
        let app = manager.access::<EthereumApp>().unwrap();
        let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/1").expect("Invalid HDPath");
        let tx: Vec<u8> = hex::decode("ec038504a817c8008252089478296f1058dd49c5d6500855f59094f0a2876397880de0b6b3a764000080018080").unwrap();
        let signed = app.sign_transaction(tx.as_slice(), &hdpath);
        channel_tx.send(signed);
    });

    speculos.accept_on_screen().unwrap();

    let signed = channel_rx.recv().unwrap();

    assert!(signed.is_ok());
    let signature = signed.unwrap();

    assert_eq!("2613ad946bd71c273f54efd87f5852c4ae275a80b644f921879fc4b7ee4d3e574829c34a51194ff20102aa4e93e698d01bf49ca4672005e73fb012792bc9dd5a27", hex::encode(signature));
}

#[test]
pub fn sign_tx_eip1559() {
    // send 1 ETH to 0x78296F1058dD49C5D6500855F59094F0a2876397 paying 20gwei max + 1gwei priority for gas and nonce 3

    let (channel_tx, channel_rx) = mpsc::channel();
    let mut manager = LedgerSpeculosKey::new().unwrap();
    manager.connect().expect("Not connected");
    let speculos = Speculos::create_env();

    spawn(move || {
        let app = manager.access::<EthereumApp>().unwrap();
        let hdpath = StandardHDPath::try_from("m/44'/60'/0'/0/1").expect("Invalid HDPath");
        let tx: Vec<u8> = hex::decode("02f00103843b9aca008504a817c8008252089478296f1058dd49c5d6500855f59094f0a2876397880de0b6b3a764000080c0").unwrap();
        let signed = app.sign_transaction(tx.as_slice(), &hdpath);
        channel_tx.send(signed);
    });

    speculos.accept_on_screen().unwrap();

    let signed = channel_rx.recv().unwrap();

    assert!(signed.is_ok());
    let signature = signed.unwrap();

    assert_eq!("008c0a3d0f9410ab3a77cc4d2e824a9b689e39de4d7deb6d5006046dc2ba42f0907a15d04bad09f1b29689fd3e09cbe384e615296314581f16b6c6148c4c48c05b", hex::encode(signature));
}