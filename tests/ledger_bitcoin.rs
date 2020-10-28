#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use emerald_hwkey::{
    ledger::manager::LedgerKey,
    ledger::app_bitcoin::{BitcoinApp, GetAddressOpts, AddressType, UnsignedInput, SignTx, BitcoinApps},
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
use hdpath::{StandardHDPath, AccountHDPath};
use std::convert::TryFrom;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use bitcoin::util::psbt::serialize::Deserialize;
use bitcoin::util::bip32::{ExtendedPubKey, Fingerprint, ChildNumber};
use secp256k1::Secp256k1;
use std::thread;
use emerald_hwkey::ledger::traits::{PubkeyAddressApp, LedgerApp};

lazy_static! {
    static ref LOG_CONF: () = SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn is_bitcoin_open() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);
    let open = app.is_open();
    assert_eq!(Some(BitcoinApps::Mainnet), open);
}

#[test]
#[cfg(not(ledger_bitcoin))]
pub fn is_bitcoin_closed() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);
    let open = app.is_open();
    assert_ne!(Some(BitcoinApps::Mainnet), open);
}

#[test]
#[cfg(ledger_bitcoin_test)]
pub fn is_bitcoin_test_open() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);
    let open = app.is_open();
    assert_eq!(Some(BitcoinApps::Testnet), open);
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0365fa75cc427606b99d9aaa326fdc7d0d30add37c545c5795eab1112839ccb406");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qutnalcwjea9zf38vgczkncw8svdc9gzyslavwn").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0223e3b63f8bfec04e968b6b413242006e59e74972617543325116d836521fadb5");

    let hdpath = StandardHDPath::try_from("m/84'/0'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::default()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qtr4m7wm33c4wzywh3tgtpkkpd0wnd2lmyyqf9m").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "02cbf9b7ef45036927be859f4d0125f404ef1247878fb97c2b11c05726df0f2323");
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
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("1C8QaECCrmFJAnYt449yPH9fAXTSiPKiL3").unwrap());

    let hdpath = StandardHDPath::try_from("m/44'/0'/1'/0/55").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("1FyQq9QCTZM5s2SS9J4ow7V7hRctptnNnX").unwrap());

    let hdpath = StandardHDPath::try_from("m/44'/0'/1'/1/33").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
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
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("388YAeohMoH23UhQPzgAbreW1ZSQiFbcfM").unwrap());

    let hdpath = StandardHDPath::try_from("m/49'/0'/1'/0/55").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("3N5L6N3W3utSe17W7xAqVbgZTHkYXUQDWR").unwrap());

    let hdpath = StandardHDPath::try_from("m/49'/0'/1'/1/33").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
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
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1qglapytdh7tmu7uphfh2rczzy89a7k98z5p3era").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "0300aa53021aac8f948b391b2c6aab930f6186d0bc1d29fca81a2459e85630e18f");

    let hdpath = StandardHDPath::try_from("m/84'/1'/1'/0/5").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1quw7aafua6qe43ydvv3aj7p5xqspc6rpvzwjem4").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "023a7a069b5fcfcca78eadaf3c209f97cebae11761857e2734ed7f2d43008d5de8");

    let hdpath = StandardHDPath::try_from("m/84'/1'/1'/1/3").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, opts).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("tb1qhcfnvvdk0lth4rayz5fh9kcua5ep029lec0fds").unwrap());
    assert_eq!(hex::encode(act.pubkey.serialize()), "027943d5f3a66344a6639200e70ff6281615ec18f806d074f5369b55bb1f7cef54");
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn confirm_get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::confirm()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap());
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn compat_get_bitcoin_address() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = StandardHDPath::try_from("m/49'/3'/0'/0/0").expect("Invalid HDPath");
    let act = app.get_address(&hdpath, GetAddressOpts::compat_address()).expect("Failed to get address");
    assert_eq!(act.address, Address::from_str("36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms").unwrap());
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_xpub_0() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = AccountHDPath::try_from("m/44'/0'/0'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    let exp = ExtendedPubKey::from_str("xpub6DKpFN6ZfnVw31f2LtBtZfQ2QQocxgojbwyg63RFmC1C9k14ijNUPEPheJ3DQVjAWFHD5EeXVEZ9RKvtUhZNe5P31nivbtCo7h7dLfzRC1v").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_xpub_1() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = AccountHDPath::try_from("m/44'/0'/1'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    let exp = ExtendedPubKey::from_str("xpub6DKpFN6ZfnVw6Vm67fB1HVkRdwfHmEiDZvXrtMUmd2BavMd5onANHhVdMpYGgza4gUVULrPAoSdFy4BkSPCGcbFJ18GBC9eg7rmt5YqD9RJ").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_xpub_84_0() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = AccountHDPath::try_from("m/84'/0'/0'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    // actual = zpub6rRF9XhDBRQSKiGLTD9vTaBfdpRrxJA9eG5YHmTwFfRN2Rbv7w7XNgCZg93Gk7CdRdfjY5hwM5ugrwXak9RgVsx5fwHfAdHdbf5UKmokEtJ
    // convert with https://jlopp.github.io/xpub-converter/
    let exp = ExtendedPubKey::from_str("xpub6CkiYCMNt4KUd7t6nVag3PzfHt8y54B9p336iygAVefbvDyTccnQ8YtHdj86kHtncMS838WpRmCb6NJTJkbeuQaswFtozoef4CxBYcSAYWa").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn get_xpub_84_17() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let hdpath = AccountHDPath::try_from("m/84'/0'/17'").expect("Invalid HDPath");

    let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
    // actual = zpub6rRF9XhDBRQT6HfqmRBeQkQ9JVswt45EoPFgEMZtysrJwPZcNRJ7mQCrnPcomdyRBV95Cj2cHWusvAafHvUZCLoJDw2Dy7GyqjXjg36r7zb
    // convert with https://jlopp.github.io/xpub-converter/
    let exp = ExtendedPubKey::from_str("xpub6CkiYCMNt4KVPhHc6hcPzaD8xZb3zp6EyADEfZn8Ds6YqBw9s6xzXGtajyhdmpfaNCuThmqVNCCn9bMXrXeXbsS6VFdNoHe1JHQSttAp1nc").unwrap();

    assert_eq!(act, exp);
}

#[test]
#[cfg(ledger_bitcoin)]
pub fn address_within_xpub() {
    let mut manager = LedgerKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = BitcoinApp::new(manager);

    let secp = Secp256k1::new();

    let hdpath = AccountHDPath::try_from("m/84'/0'/2'").expect("Invalid HDPath");
    let xpub = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");

    for change in &[0u32, 1] {
        for index in &[0u32, 1, 2, 5, 7, 10, 16, 64, 100, 150, 500, 1000, 15861, 71591, 619691] {
            let address_exp = Address::p2wpkh(
                &xpub.derive_pub(&secp, &vec![
                    ChildNumber::from_normal_idx(*change).unwrap(),
                    ChildNumber::from_normal_idx(*index).unwrap()
                ]).unwrap().public_key,
                Network::Bitcoin,
            ).unwrap();
            let address_act = app.get_address(
                &hdpath.address_at(*change, *index).unwrap(),
                GetAddressOpts::default(),
            ).unwrap().address;

            // println!("verify address {:} at {:}", address_act, hdpath.address_at(*change, *index).unwrap().to_string());
            assert_eq!(address_exp, address_act);

            // because ledger may stuck if call it too fast
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
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
        &StandardHDPath::from_str("m/84'/1'/0'/0/0").unwrap(),
        GetAddressOpts {
            network: Network::Testnet,
            ..GetAddressOpts::default()
        },
    ).unwrap();
    let from_pubkey = from_full.pubkey;
    tx.input[0].witness = vec![signature[0].clone(), from_pubkey.key.serialize().to_vec()];
    println!("Signed: {}", hex::encode(tx.serialize()));

    let signatures: Vec<String> = signature.iter().map(hex::encode).collect();
    assert_eq!(vec![
        "304402202ffaf3d2856ecb77485064b02216870596881ed2387b2e01d82fb91b9c26b6ff02206408c6cbf17123bf5ae4678030e0d557b8794690cd822f72999b0b2c49dc0b8501"
    ], signatures);
}