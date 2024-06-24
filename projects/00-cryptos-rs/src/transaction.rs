use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::bitcoin::BITCOIN;
use crate::keys::PublicKey;
use crate::ripemd160::ripemd160;
use crate::sha256::{hash256, sha256};
use crate::signature::{verify_ecdsa, Signature};
use crate::utils;

pub struct TxFetcher {
    cache: HashMap<String, Tx>,
}

impl TxFetcher {
    pub fn fetch(tx_id: &str, net: &str) -> Tx {
        assert!(tx_id.chars().all(|c| c.is_ascii_hexdigit()));
        let tx_id = tx_id.to_lowercase();
        let txdb_dir = "txdb";
        let cache_file = format!("{}/{}", txdb_dir, tx_id);

        let raw = if std::path::Path::new(&cache_file).exists() {
            std::fs::read(&cache_file).unwrap()
        } else {
            let url = match net {
                "main" => format!("https://blockstream.info/api/tx/{}/hex", tx_id),
                "test" => format!("https://blockstream.info/testnet/api/tx/{}/hex", tx_id),
                _ => panic!("{} is not a valid net type, should be main|test", net),
            };
            let response = reqwest::blocking::get(&url).unwrap();
            assert!(
                response.status().is_success(),
                "transaction id {} was not found on blockstream",
                tx_id
            );
            let raw = hex::decode(response.text().unwrap().trim()).unwrap();
            std::fs::create_dir_all(txdb_dir).unwrap();
            std::fs::write(&cache_file, &raw).unwrap();
            raw
        };

        let mut cursor = Cursor::new(&raw);
        let tx = Tx::decode(&mut cursor);
        assert_eq!(tx.id(), tx_id);
        tx
    }
}

#[derive(Debug, Default)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub locktime: u32,
    pub segwit: bool,
}

impl Tx {
    pub fn decode(s: &mut Cursor<&Vec<u8>>) -> Self {
        let version = utils::read_u32(s).unwrap();
        let segwit = utils::read_u8(s).unwrap() == 0;
        let tx_in_count = utils::read_varint(s).unwrap();
        let tx_ins = (0..tx_in_count).map(|_| TxIn::decode(s)).collect();
        let tx_out_count = utils::read_varint(s).unwrap();
        let tx_outs = (0..tx_out_count).map(|_| TxOut::decode(s)).collect();
        let locktime = utils::read_u32(s).unwrap();
        Tx {
            version,
            tx_ins,
            tx_outs,
            locktime,
            segwit,
        }
    }

    pub fn encode(&self, force_legacy: bool, _sig_index: Option<usize>) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&self.version.to_le_bytes());
        if self.segwit && !force_legacy {
            result.push(0);
        }
        result.extend(utils::encode_varint(self.tx_ins.len() as u64));
        for tx_in in &self.tx_ins {
            result.extend(tx_in.encode(None));
        }
        result.extend(utils::encode_varint(self.tx_outs.len() as u64));
        for tx_out in &self.tx_outs {
            result.extend(tx_out.encode());
        }
        result.extend(&self.locktime.to_le_bytes());
        result
    }

    pub fn id(&self) -> String {
        hex::encode(hash256(self.encode(true, None)))
    }

    pub fn fee(&self) -> u64 {
        let input_total: u64 = self.tx_ins.iter().map(|tx_in| tx_in.value()).sum();
        let output_total: u64 = self.tx_outs.iter().map(|tx_out| tx_out.amount).sum();
        input_total - output_total
    }

    pub fn validate(&self) -> bool {
        if self.segwit {
            return false; // TODO: Implement segwit validation
        }

        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let mod_tx_enc = self.encode(false, Some(i));
            let combined = tx_in.script_sig.clone() + tx_in.script_pubkey();
            if !combined.evaluate(&mod_tx_enc) {
                return false;
            }
        }

        true
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_ins.len() == 1
            && self.tx_ins[0].prev_tx == vec![0; 32]
            && self.tx_ins[0].prev_index == 0xffffffff
    }

    pub fn coinbase_height(&self) -> Option<u32> {
        if self.is_coinbase() {
            Some(u32::from_le_bytes(
                self.tx_ins[0].script_sig.cmds[0]
                    .clone()
                    .try_into()
                    .unwrap(),
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>,
    pub prev_index: u32,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
    pub net: String,
}

impl TxIn {
    pub fn decode(s: &mut Cursor<&Vec<u8>>) -> Self {
        let mut prev_tx = vec![0; 32];
        s.read_exact(&mut prev_tx).unwrap();
        let prev_index = utils::read_u32(s).unwrap();
        let script_sig = Script::decode(s);
        let sequence = utils::read_u32(s).unwrap();
        TxIn {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
            witness: vec![],
            net: String::new(),
        }
    }

    pub fn encode(&self, script_override: Option<bool>) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&self.prev_tx);
        result.extend(&self.prev_index.to_le_bytes());
        result.extend(self.script_sig.encode());
        result.extend(&self.sequence.to_le_bytes());
        result
    }

    pub fn value(&self) -> u64 {
        // Look up the amount in the previous transaction
        let tx = TxFetcher::fetch(&hex::encode(&self.prev_tx), &self.net);
        tx.tx_outs[self.prev_index as usize].amount
    }

    pub fn script_pubkey(&self) -> Script {
        // Look up the script_pubkey in the previous transaction
        let tx = TxFetcher::fetch(&hex::encode(&self.prev_tx), &self.net);
        tx.tx_outs[self.prev_index as usize].script_pubkey.clone()
    }
}

#[derive(Debug, Default, Clone)]
pub struct TxOut {
    amount: u64,
    script_pubkey: Script,
}

impl TxOut {
    pub fn decode(s: &mut Cursor<&Vec<u8>>) -> Self {
        let amount = utils::read_u64(s).unwrap();
        let script_pubkey = Script::decode(s);
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(&self.amount.to_le_bytes());
        result.extend(self.script_pubkey.encode());
        result
    }
}

const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;

#[derive(Debug, Default, Clone)]
pub struct Script {
    pub cmds: Vec<Vec<u8>>,
}

impl Script {
    pub fn decode(s: &mut Cursor<&Vec<u8>>) -> Self {
        let length = utils::read_varint(s).unwrap() as usize;
        let mut cmds = vec![];
        for _ in 0..length {
            let cmd_length = utils::read_u8(s).unwrap() as usize;
            let mut cmd = vec![0; cmd_length];
            s.read_exact(&mut cmd).unwrap();
            cmds.push(cmd);
        }
        Script { cmds }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = vec![];
        result.extend(utils::encode_varint(self.cmds.len() as u64));
        for cmd in &self.cmds {
            result.push(cmd.len() as u8);
            result.extend(cmd);
        }
        result
    }

    pub fn evaluate(&self, mod_tx_enc: &[u8]) -> bool {
        // Ensure the script is a standard P2PKH transaction
        if self.cmds.len() != 7 {
            return false;
        }

        // Extract the commands
        let signature = &self.cmds[0];
        let pubkey = &self.cmds[1];
        let op_dup = self.cmds[2][0];
        let op_hash160 = self.cmds[3][0];
        let pubkey_hash = &self.cmds[4];
        let op_equalverify = self.cmds[5][0];
        let op_checksig = self.cmds[6][0];

        // Verify the opcodes
        if op_dup != OP_DUP
            || op_hash160 != OP_HASH160
            || op_equalverify != OP_EQUALVERIFY
            || op_checksig != OP_CHECKSIG
        {
            return false;
        }

        // Verify the public key hash
        if *pubkey_hash != ripemd160(&sha256(pubkey.to_vec())) {
            return false;
        }

        // Verify the digital signature
        let sighash_type = signature[signature.len() - 1];
        if sighash_type != 1 {
            return false;
        }
        let der = &signature[..signature.len() - 1];
        let sig = Signature::decode(der);
        let pk = PublicKey::from_bytes(pubkey, &BITCOIN.gen.G.curve);
        verify_ecdsa(&pk, mod_tx_enc, &sig)
    }
}

impl std::ops::Add for Script {
    type Output = Script;

    fn add(self, other: Script) -> Script {
        let mut cmds = self.cmds.clone();
        cmds.extend(other.cmds);
        Script { cmds }
    }
}
