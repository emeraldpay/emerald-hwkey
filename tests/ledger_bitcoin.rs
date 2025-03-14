#![allow(unused_imports)]
#![allow(dead_code)]
#![cfg(all(integration_test, test_bitcoin))]


use lazy_static::lazy_static;
use log::LevelFilter;
use emerald_hwkey::ledger::app::{BitcoinApp, LedgerApp};
use emerald_hwkey::ledger::app::bitcoin::BitcoinApps;
use emerald_hwkey::ledger::connect::{LedgerHidKey, LedgerKey};
use simple_logger::SimpleLogger;

lazy_static! {
    static ref LOG_CONF: () = SimpleLogger::new().with_level(LevelFilter::Trace).init().unwrap();
}

pub fn is_bitcoin_open() {
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<BitcoinApp>().unwrap();
    let open = app.is_open();
    assert_eq!(Some(BitcoinApps::Mainnet), open);
}

pub fn is_bitcoin_closed() {
    let mut manager = LedgerHidKey::new().unwrap();
    manager.connect().expect("Not connected");
    let app = manager.access::<BitcoinApp>().unwrap();
    let open = app.is_open();
    assert_ne!(Some(BitcoinApps::Mainnet), open);
}

#[cfg(not(test_bitcoin_testnet))]
mod mainnet {
    use std::str::FromStr;
    use bitcoin::{Address, Network};
    use bitcoin::psbt::serialize::Serialize;
    use bitcoin::util::bip32::ExtendedPubKey;
    use hdpath::{AccountHDPath, StandardHDPath};
    use emerald_hwkey::ledger::app::bitcoin::{AddressType, GetAddressOpts};
    use emerald_hwkey::ledger::app::{BitcoinApp, PubkeyAddressApp};
    use emerald_hwkey::ledger::connect::{LedgerHidKey, LedgerKey};

    #[test]
    pub fn get_bitcoin_address() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

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
    pub fn get_bitcoin_address_legacy() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

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
    pub fn get_bitcoin_address_segwit_compat() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

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
    pub fn confirm_get_bitcoin_address() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = StandardHDPath::try_from("m/84'/0'/0'/0/0").expect("Invalid HDPath");
        let act = app.get_address(&hdpath, GetAddressOpts::confirm()).expect("Failed to get address");
        assert_eq!(act.address, Address::from_str("bc1qaaayykrrx84clgnpcfqu00nmf2g3mf7f53pk3n").unwrap());
    }

    #[test]
    pub fn compat_get_bitcoin_address() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = StandardHDPath::try_from("m/49'/3'/0'/0/0").expect("Invalid HDPath");
        let act = app.get_address(&hdpath, GetAddressOpts::compat_address()).expect("Failed to get address");
        assert_eq!(act.address, Address::from_str("36rYHXjrQp5uJVfZfdW5Y3FvqGDFDVhtms").unwrap());
    }

    #[test]
    pub fn get_xpub_0() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = AccountHDPath::try_from("m/44'/0'/0'").expect("Invalid HDPath");

        let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
        let exp = ExtendedPubKey::from_str("xpub6DKpFN6ZfnVw31f2LtBtZfQ2QQocxgojbwyg63RFmC1C9k14ijNUPEPheJ3DQVjAWFHD5EeXVEZ9RKvtUhZNe5P31nivbtCo7h7dLfzRC1v").unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    pub fn get_xpub_1() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = AccountHDPath::try_from("m/44'/0'/1'").expect("Invalid HDPath");

        let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
        let exp = ExtendedPubKey::from_str("xpub6DKpFN6ZfnVw6Vm67fB1HVkRdwfHmEiDZvXrtMUmd2BavMd5onANHhVdMpYGgza4gUVULrPAoSdFy4BkSPCGcbFJ18GBC9eg7rmt5YqD9RJ").unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    pub fn get_xpub_84_0() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = AccountHDPath::try_from("m/84'/0'/0'").expect("Invalid HDPath");

        let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
        // actual = zpub6rRF9XhDBRQSKiGLTD9vTaBfdpRrxJA9eG5YHmTwFfRN2Rbv7w7XNgCZg93Gk7CdRdfjY5hwM5ugrwXak9RgVsx5fwHfAdHdbf5UKmokEtJ
        // convert with https://jlopp.github.io/xpub-converter/
        let exp = ExtendedPubKey::from_str("xpub6CkiYCMNt4KUd7t6nVag3PzfHt8y54B9p336iygAVefbvDyTccnQ8YtHdj86kHtncMS838WpRmCb6NJTJkbeuQaswFtozoef4CxBYcSAYWa").unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    pub fn get_xpub_84_17() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = AccountHDPath::try_from("m/84'/0'/17'").expect("Invalid HDPath");

        let act = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");
        // actual = zpub6rRF9XhDBRQT6HfqmRBeQkQ9JVswt45EoPFgEMZtysrJwPZcNRJ7mQCrnPcomdyRBV95Cj2cHWusvAafHvUZCLoJDw2Dy7GyqjXjg36r7zb
        // convert with https://jlopp.github.io/xpub-converter/
        let exp = ExtendedPubKey::from_str("xpub6CkiYCMNt4KVPhHc6hcPzaD8xZb3zp6EyADEfZn8Ds6YqBw9s6xzXGtajyhdmpfaNCuThmqVNCCn9bMXrXeXbsS6VFdNoHe1JHQSttAp1nc").unwrap();

        assert_eq!(act, exp);
    }
}

#[cfg(ledger_bitcoin_test)]
mod testnet {
    use std::str::FromStr;
    use bitcoin::{Address, Network, OutPoint, PackedLockTime, PublicKey, Transaction, TxIn, TxOut, Txid};
    use bitcoin::psbt::serialize::Serialize;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
    use hdpath::{AccountHDPath, StandardHDPath};
    use emerald_hwkey::ledger::app::bitcoin::{BitcoinApps, GetAddressOpts, SignTx, UnsignedInput};
    use emerald_hwkey::ledger::app::{BitcoinApp, LedgerApp, PubkeyAddressApp};
    use emerald_hwkey::ledger::connect::{LedgerHidKey, LedgerKey};

    #[test]
    pub fn test_is_bitcoin_test_open() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();
        let open = app.is_open();
        assert_eq!(Some(BitcoinApps::Testnet), open);
    }

    #[test]
    pub fn get_bitcoin_address_testnet() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

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
    pub fn get_xpub_test() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let hdpath = AccountHDPath::try_from("m/44'/1'/5'").expect("Invalid HDPath");

        let act = app.get_xpub(&hdpath, Network::Testnet).expect("Failed to get xpub");
        let exp = ExtendedPubKey::from_str("tpubDCnH31p12jTYeSH4NpWbg7s33dTQdaz2GS8wF4hjTL9wtxZaFu2qzJTcdarP6UZtCE6yZGMMVaLMdtCG9nJ3Lx999XQy9aELwcyi4xATkeo").unwrap();

        assert_eq!(act, exp);
    }

    #[test]
    pub fn address_within_xpub() {
        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();

        let secp = Secp256k1::new();

        let hdpath = AccountHDPath::try_from("m/84'/0'/2'").expect("Invalid HDPath");
        let xpub = app.get_xpub(&hdpath, Network::Bitcoin).expect("Failed to get xpub");

        for change in &[0u32, 1] {
            for index in &[0u32, 1, 2, 5, 7, 10, 16, 64, 100, 150, 500, 1000, 15861, 71591, 619691] {
                let address_exp = Address::p2wpkh(
                    &PublicKey::new(xpub.derive_pub(&secp, &vec![
                        ChildNumber::from_normal_idx(*change).unwrap(),
                        ChildNumber::from_normal_idx(*index).unwrap()
                    ]).unwrap().public_key),
                    Network::Bitcoin,
                ).unwrap();
                let address_act = app.get_address(
                    &hdpath.address_at(*change, *index).unwrap(),
                    GetAddressOpts::default(),
                ).unwrap().address;

                // println!("verify address {:} at {:}", address_act, hdpath.address_at(*change, *index).unwrap().to_string());
                assert_eq!(address_exp, address_act);

                // because ledger may stuck if call it too fast
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }

    #[test]
    pub fn sign_bitcoin_tx_1() {
        // send 0.04567677 from tb1qglapytdh7tmu7uphfh2rczzy89a7k98z5p3era at m/84'/1'/0'/0/0
        // to tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0

        let from_amount = 4567800;
        let to_amount = from_amount - 123;

        let _from_tx = hex::decode(
            "02000000000103a44b1457ed26392b5b2db07ec82b06655cdb8b8b3e9e0fdc87b5e7f1fb70cb4f0000000000fdffffff580267659dc032ff9abfd505f517cae5536f35d32340c2fc0f5bad60cd8301bc0000000000fdffffffb0ac2c5d2754f7d08d0a7149804a87f4acdc1cf946375315d0e78d89a604c9840000000000fdffffff02f8b245000000000016001447fa122db7f2f7cf70374dd43c0844397beb14e27400100000000000160014f126d5ec29cd9f11137a9b2521d7acae4bffe230024730440220259e7a1fbe2b86f7e060370d957c52d5e3895619f13d349d86ff513addf8086a02206c6d0e309534ed5c28097cf06a4f9587d78329f97552f4cfb1635f5da961a24d012103ffa3949e4cbe4f2bbef487f829ea4c4f5ebb085b19643352b1c86be74c608c060247304402205d634724f41485bc4a2f0f13a6bc68b63ccefccdb7a48fb012cee168f774ac5602201ddf559cff8fe478dc75581a9340da058dab18f3cbd16c424156d1959bd901b1012103651ad466beec0d9efcbfae469fb846441fa440f3efa079c956d9652696ff81d002473044022049a9014a540e712805f2e40c6203c18ac01d2051199069ae19b0abfda9af8d450220701d1b1ecdb5cb84364725ffd84e03a10c0041e295172ed92da9dd08d6b2ef900121033f571fb80d1371dfb65605e3515b658564e2ff578d105494eb9403b2dc5fff8c64701c00"
        ).unwrap();

        let mut tx = Transaction {
            version: 2,
            lock_time: bitcoin::PackedLockTime(0),
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid::from_str("41217d32e29b67d01692eed0ca776ea24a9f03299dfc46dde1bf14d3918e5275").unwrap(), 0),
                    sequence: bitcoin::Sequence(0xfffffffd),
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

        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();
        let signed = app.sign_tx(&mut tx, &SignTx {
            inputs: vec![
                UnsignedInput {
                    index: 0,
                    amount: from_amount,
                    hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/0").unwrap(),
                }
            ],
            network: Network::Testnet,
        });
        assert!(signed.is_ok(), "Not ok {:?}", signed);
        println!("Signed: {}", hex::encode(tx.serialize()));

        assert_eq!(
            tx.input[0].witness.iter().map(|x| hex::encode(x)).collect::<Vec<String>>(),
            vec![
                "304402202ffaf3d2856ecb77485064b02216870596881ed2387b2e01d82fb91b9c26b6ff02206408c6cbf17123bf5ae4678030e0d557b8794690cd822f72999b0b2c49dc0b8501".to_string(),
                "0300aa53021aac8f948b391b2c6aab930f6186d0bc1d29fca81a2459e85630e18f".to_string()
            ]
        );
    }

    #[test]
    pub fn sign_bitcoin_tx_2() {
        // utxo:
        // aa622e3b4822e4a4339d9491c5b9b55716ee30ff9d9a1654f393889dbd8f45aa : 1 -> 0.06816000 -> tb1ql8w3c87jhw3d8xkydvpsatgn526f33p3cqm3vm
        // 64e0a9a5b16b97af23f7e20da888ba7b8944ef338259e53f0dfb40714f8391b3 : 0 -> 0.08156100 -> tb1qcwv8vf3uxkrdfgdr0z89jg0qfa6tauenzq0vrl
        // 1d868fe284c925ac4b1280c12ba9ffd11cca3d45dd1fac3d0756cd72903fdb34 : 1 -> 0.02000000 -> tb1ql8w3c87jhw3d8xkydvpsatgn526f33p3cqm3vm
        //
        // send 0.06816000 from tb1ql8w3c87jhw3d8xkydvpsatgn526f33p3cqm3vm at m/84'/1'/0'/0/1
        // send 0.08156100 from tb1qcwv8vf3uxkrdfgdr0z89jg0qfa6tauenzq0vrl at m/84'/1'/0'/0/2
        // send 0.02000000 from tb1ql8w3c87jhw3d8xkydvpsatgn526f33p3cqm3vm at m/84'/1'/0'/0/1
        //
        // total: 0.06816000 + 0.08156100 + 0.02 = 0.16972100
        //
        // as 0.15 to tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0
        // change 0.01971643 to tb1qe8nwur644jfmsazsnmj903kr70sqnt3n9vjvlh at m/84'/1'/0'/1/0


        let amount1 = 6_816_000;
        let amount2 = 8_156_100;
        let amount3 = 2_000_000;

        let send = 15_000_000;
        let fee = 457;
        let change = amount1 + amount2 + amount3 - fee - send; // 1_972_100

        let _from_tx_1 = hex::decode(
            "020000000001034ab029102f9545985dffeb84aa6c131b3aa2cca845e9af3f36fbab87bfd7c4630000000000fdffffff75528e91d314bfe1dd46fc9d29039f4aa26e77cad0ee9216d0679be2327d21410100000000fdffffff59fccb92f9fc864d2d859ca8138e41b819fd19a174c655e252b8d28e06d8cef60000000000fdffffff028dfd130000000000160014fdc9064a34c6832e9202890de348e28dea2203020001680000000000160014f9dd1c1fd2bba2d39ac46b030ead13a2b498c431024730440220349f9d1c2cfaf5860846c57bb3f737983b317374cfc6004c119c106bff8f7ea602203e2e711c901152369fa7e07c351600aeec8fe2ae12fa0c541e2866eec27b5dc70121026f1663582f56320136945949907af2560e09174fbaef222e0ecf3ec42f02964602473044022061aef3df16bb75f999f5a7a41b2eb8f58c0e1ad5c95f9f344dfe6c1d7dca1b2602202d92e72f5a28e04dc8f351cf921acbeb344ebf36f16f8d0a11ebc9b9f4e2c5c00121023146a3f0c25e3ce822010df2c7e7c94fde8b62d8b681e5b1cd6be7500cc00b980247304402206f1dec73409fa0627f5c9db1bcedb6bc65cb1456f6a6371675c2a8721e568f27022017daaf822f37c7375e45a5575072eace263176ead227a1a995c489c0d347ca2a012102e7d687dccbb4e087ee6be08905c751b414cdbb2a5d0f07b32d3bd21ddcee3bad9a761c00"
        ).unwrap();
        let _from_tx_2 = hex::decode(
            "020000000001010c9e59b769dda1f07f6a5ee73dc1d03f700cb72c58ebe8d93605777fde5e600f0000000000fdffffff02c4737c0000000000160014c39876263c3586d4a1a3788e5921e04f74bef333ba84b60000000000160014a3bd8d0f8079c950809dcebb3b2f8096b63ac7b302473044022005130b3beadd1a81ea1d81a5bf0a6c88411041e98b128190878c3624a415e31b022035fc326373addd51de03843e0965c66e6b88c719d0b7feb0837dd21dcf9eb364012102da15fdbeabe35e1ba5b1c04b39027486ca5d9a3b8e1869717f6d26b11a06e0499a761c00"
        ).unwrap();
        let _from_tx_3 = hex::decode(
            "02000000000101b391834f7140fb0d3fe5598233ef44897bba88a80de2f723af976bb1a5a9e0640100000000fdffffff02adff970000000000160014e3efd5d060de856a57960be437d7ea9644950bc280841e0000000000160014f9dd1c1fd2bba2d39ac46b030ead13a2b498c431024730440220629ccd06036cc0e28323a07a12eb723986d8bf3fe8912ab1c8bf0e4a78d82b920220298379996b203fa064d04552f444e1afdcee97e167d5458b5e0d85302b5314850121027e5b6c86962e5b1bcb4c06a6503c29ac542a56451c562361849bea0a2efa340f9c761c00"
        ).unwrap();

        let mut tx = Transaction {
            version: 2,
            lock_time: PackedLockTime(0),
            input: vec![
                TxIn {
                    previous_output: OutPoint::new(Txid::from_str("aa622e3b4822e4a4339d9491c5b9b55716ee30ff9d9a1654f393889dbd8f45aa").unwrap(), 1),
                    sequence: bitcoin::Sequence(0xfffffffd),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(Txid::from_str("64e0a9a5b16b97af23f7e20da888ba7b8944ef338259e53f0dfb40714f8391b3").unwrap(), 0),
                    sequence: bitcoin::Sequence(0xfffffffd),
                    ..TxIn::default()
                },
                TxIn {
                    previous_output: OutPoint::new(Txid::from_str("1d868fe284c925ac4b1280c12ba9ffd11cca3d45dd1fac3d0756cd72903fdb34").unwrap(), 1),
                    sequence: bitcoin::Sequence(0xfffffffd),
                    ..TxIn::default()
                }
            ],
            output: vec![
                TxOut {
                    value: send,
                    script_pubkey: Address::from_str("tb1qg9zx7vnkfs8yaycm66wz5tat6d9x29wrezhcr0").unwrap().script_pubkey(),
                },
                TxOut {
                    value: change,
                    script_pubkey: Address::from_str("tb1qe8nwur644jfmsazsnmj903kr70sqnt3n9vjvlh").unwrap().script_pubkey(),
                }
            ],
        };

        let sign_with = SignTx {
            inputs: vec![
                UnsignedInput {
                    index: 0,
                    amount: amount1,
                    hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/1").unwrap(),
                },
                UnsignedInput {
                    index: 1,
                    amount: amount2,
                    hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/2").unwrap(),
                },
                UnsignedInput {
                    index: 2,
                    amount: amount3,
                    hd_path: StandardHDPath::from_str("m/84'/1'/0'/0/1").unwrap(),
                },
            ],
            network: Network::Testnet,
        };

        let mut manager = LedgerHidKey::new().unwrap();
        manager.connect().expect("Not connected");
        let app = manager.access::<BitcoinApp>().unwrap();
        let signed = app.sign_tx(&mut tx, &sign_with);
        assert!(signed.is_ok(), "Not ok {:?}", signed);
        println!("Signed: {}", hex::encode(tx.serialize()));

        assert_eq!(
            tx.input[0].witness.iter().map(|x| hex::encode(x)).collect::<Vec<String>>(),
            vec![
                "3045022100d71ee83eeae9757714bfe9e2e8cdc02101078bba281fbf8650e72989e1f22ff202206ef8c1f6d96a7fb61ec500674d48f516af0b70daac52184fa13d32825e877c2801".to_string(),
                "028553b40b6b0bb1f52f31af64514d2e6d1c464c65be7bab76107ce328629d227e".to_string()
            ]
        );
        assert_eq!(
            tx.input[1].witness.iter().map(|x| hex::encode(x)).collect::<Vec<String>>(),
            vec![
                "3045022100fc187fd6dafeca6e1808f7c519f53c8588994000a32c007858ec711bbd64a40b022018fe935a497f5c5edf4757f794daaab0788fbc4e025e151ecf51be9598c9a4c701".to_string(),
                "03d65ae37051f01adbe94102af6b56039992f35e50ac443568c9cc82ad3a3478d7".to_string()
            ]
        );
        assert_eq!(
            tx.input[2].witness.iter().map(|x| hex::encode(x)).collect::<Vec<String>>(),
            vec![
                "304402205f156688330ab1add360651b879f0a660b10e9f653bdf2aa4921e4681311d32b02203b9c620d680781979ef1fc7fd50eabfb56e8d9b2a6ab8b9bd1fa4218cd77570a01".to_string(),
                "028553b40b6b0bb1f52f31af64514d2e6d1c464c65be7bab76107ce328629d227e".to_string()
            ]
        );
    }
}