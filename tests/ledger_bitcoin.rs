#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use emerald_hwkey::{
    ledger::manager::LedgerKey,
    ledger::app_bitcoin::{BitcoinApp, GetAddressOpts, AddressType, UnsignedInput, SignTx},
};
use bitcoin::{
    Address,
    Network,
    Transaction,
    TxIn,
    TxOut,
    OutPoint,
    Txid,
    util::psbt::serialize::Serialize,
};
use std::str::FromStr;
use hdpath::StandardHDPath;
use std::convert::TryFrom;
use log::LevelFilter;
use simple_logger::SimpleLogger;

lazy_static! {
    static ref LOG_CONF: () = SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0465fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406198798942cc6ccac5cc1933b584b23a82f66278513f38a4765e0cdf44b11d5eb");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qutnalcwjea9zf38vgczkncw8svdc9gzyslavwn").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0423e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb548bac4825b5175c971a4bcae42d75ba622f130048860099a2548980e6e9c0640");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qtr4m7wm33c4wzywh3tgtpkkpd0wnd2lmyyqf9m").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "04cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323833595ea361631ffeef009b8fa760073a7943a904e04b5dca373fdfd91b1d834");
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_bitcoin_address_legacy() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let opts = GetAddressOpts {
        address_type: AddressType::Legacy,
        ..GetAddressOpts::default()
    };

    let hdpath = StandardHDPath::try_from("m/44'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("1C8QaECCrmFJAnYt449yPH9fAXTSiPKiL3").unwrap());

    let hdpath = StandardHDPath::try_from("m/44'/0'/1'/0/55").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("1FyQq9QCTZM5s2SS9J4ow7V7hRctptnNnX").unwrap());

    let hdpath = StandardHDPath::try_from("m/44'/0'/1'/1/33").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("1EzY1L83ThJqZMznLAEninjQximpg5A2em").unwrap());
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_bitcoin_address_segwit_compat() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let opts = GetAddressOpts {
        address_type: AddressType::SegwitCompat,
        ..GetAddressOpts::default()
    };

    let hdpath = StandardHDPath::try_from("m/49'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("388YAeohMoH23UhQPzgAbreW1ZSQiFbcfM").unwrap());

    let hdpath = StandardHDPath::try_from("m/49'/0'/1'/0/55").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("3N5L6N3W3utSe17W7xAqVbgZTHkYXUQDWR").unwrap());

    let hdpath = StandardHDPath::try_from("m/49'/0'/1'/1/33").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("3LUJrf27afymiyZskzcLBmeECKfagsV6xz").unwrap());
}

#[test]
#[cfg(ledger_bitcoin_test)]
pub fn get_bitcoin_address_testnet() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let opts = GetAddressOpts {
        network: Network::Testnet,
        ..GetAddressOpts::default()
    };

    let hdpath = StandardHDPath::try_from("m/84'/1'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1qglapytdh7tmu7uphfh2rczzy89a7k98z5p3era").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0400aa53021aac8f948b391b2c6aab930f6186d0bc1d29fca81a2459e85630e18ff965743d0be542b4f8ccfdaf40d4dc4b7002e8fab541f71009866c3993f60e8d");

    let hdpath = StandardHDPath::try_from("m/84'/1'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1quw7aafua6qe43ydvv3aj7p5xqspc6rpvzwjem4").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "043a7a069b5fcfcca78eadaf3c209f97cebae11761857e2734ed7f2d43008d5de8e248d594bf9d7cf0d6fdc441673e8e1f3e54eb0e4a6ac24bedfa5eec1546814e");

    let hdpath = StandardHDPath::try_from("m/84'/1'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1qhcfnvvdk0lth4rayz5fh9kcua5ep029lec0fds").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "047943d5f3a66344a6639200e70ff6281615ec18f806d074f5369b55bb1f7cef5440712fa9382c9dea661a7250456f8752fd4246ccb5dc00457661e1f446d49c5a");
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn confirm_get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::confirm()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap());
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn compat_get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/49'/3'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(hdpath.to_bytes(), GetAddressOpts::compat_address()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms").unwrap());
}


#[test]
#[cfg(ledger_bitcoin_test)]
pub fn sign_bitcoin_tx() {
    // send 0.04567677 from tb1qglapytdh7tmu7uphfh2rczzy89a7k98z5p3era at m/84'/1'/0'/0/0
    // to tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0

    let from_amount = 4567800;
    let to_amount = from_amount - 123;

    let from_tx = hex::decode(
        "02000000000103a44b1457ed26392b5b2db07ec82b06655cdb8b8b3e9e0fdc87b5e7f1fb70cb4f0000000000fdffffff580267659dc032ff9abfd505f517cae5536f35d32340c2fc0f5bad60cd8301bc0000000000fdffffffb0ac2c5d2754f7d08d0a7149804a87f4acdc1cf946375315d0e78d89a604c9840000000000fdffffff02f8b245000000000016001447fa122db7f2f7cf70374dd43c0844397beb14e27400100000000000160014f126d5ec29cd9f11137a9b2521d7acae4bffe230024730440220259e7a1fbe2b86f7e060370d957c52d5e3895619f13d349d86ff513addf8086a02206c6d0e309534ed5c28097cf06a4f9587d78329f97552f4cfb1635f5da961a24d012103ffa3949e4cbe4f2bbef487f829ea4c4f5ebb085b19643352b1c86be74c608c060247304402205d634724f41485bc4a2f0f13a6bc68b63ccefccdb7a48fb012cee168f774ac5602201ddf559cff8fe478dc75581a9340da058dab18f3cbd16c424156d1959bd901b1012103651ad466beec0d9efcbfae469fb846441fa440f3efa079c956d9652696ff81d002473044022049a9014a540e712805f2e40c6203c18ac01d2051199069ae19b0abfda9af8d450220701d1b1ecdb5cb84364725ffd84e03a10c0041e295172ed92da9dd08d6b2ef900121033f571fb80d1371dfb65605e3515b658564e2ff578d105494eb9403b2dc5fff8c64701c00"
    ).unwrap();

    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint::new(Txid::from_str("41217d32e29b67d01692eed0ca776ea24a9f03299dfc46dde1bf14d3918e5275").unwrap(), 0),
                sequence: 0xfffffffd,
                ..TxIn::default()
            }
        ],
        output: vec![
            TxOut {
                // 0x45B27D --encode-> 7db245
                value: to_amount, // = 4567677
                script_pubkey: Address::from_str("tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0").unwrap().script_pubkey(),
            }
        ],
    };

    println!("Sign tx {}", hex::encode(tx.serialize()));

    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);
    let signature = app.sign_tx(&SignTx {
        raw: tx.serialize(),
        inputs: vec![
            UnsignedInput {
                raw: from_tx,
                amount: from_amount,
                hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                vout: 0,
            }
        ],
        network: Network::Testnet,
    });
    assert!(signature.is_ok(), format!("Not ok {:?}", signature));
    let signature = signature.unwrap();


    let from_full = app.get_address(
        StandardHDPath::from_str("m/84'/1'/0'/0/0").unwrap().to_bytes(),
        GetAddressOpts {
            network: Network::Testnet,
            ..GetAddressOpts::default()
        },
    ).unwrap();
    let from_pubkey = from_full.pubkey;
    tx.input[0].witness = vec![signature[0].clone(), from_pubkey.key.serialize().to_vec()];
    println!("Signed: {}", hex::encode(tx.serialize()));

    let signatures: Vec<String> = signature.iter().map(hex::encode).collect();
    // assert_eq!(vec![
    //     "30..."
    // ], signatures);
}