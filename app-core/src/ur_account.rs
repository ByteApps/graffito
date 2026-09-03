//! Decode UR hardware-wallet account exports into output descriptors, so a
//! funding wallet can be imported by scanning the device's "export account" QR.
//!
//! Handles (BCR-2020-007/010/015):
//!   * `crypto-account`            — master fingerprint + an array of descriptors
//!   * `crypto-output-descriptor`  — one descriptor (old tagged form OR the newer
//!     text-`source` map)
//!   * `crypto-hdkey`              — a bare account xpub (taken as taproot BIP-86)
//!
//! Only the single-sig `tr(...)` (tag 409) and `wpkh(...)` (tag 404) script
//! types are surfaced — the two the funding builder supports. The account xpub
//! is always wrapped as a multipath `…/<0;1>/*` descriptor.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::secp256k1::PublicKey;
use bitcoin::NetworkKind;
use ciborium::value::{Integer, Value};

use crate::Error;

const TAG_HDKEY: u64 = 303;
const TAG_WPKH: u64 = 404;
const TAG_TR: u64 = 409;

/// A descriptor recovered from a UR account export.
#[derive(Debug, Clone)]
pub struct AccountDescriptor {
    pub kind: String, // "taproot" | "segwit"
    pub descriptor: String,
}

/// Decode account/descriptor UR CBOR into one or more funding descriptors.
pub fn descriptors_from_ur(
    ur_type: &str,
    cbor: &[u8],
    network: notes_core::Network,
) -> Result<Vec<AccountDescriptor>, Error> {
    let value: Value =
        ciborium::from_reader(cbor).map_err(|e| Error::Ur(format!("cbor: {e}")))?;
    match ur_type {
        "crypto-account" | "account" => account_descriptors(&value, network),
        "crypto-output-descriptor" | "output-descriptor" | "output" => {
            Ok(output_descriptor(&value, network).into_iter().collect())
        }
        "crypto-hdkey" | "hdkey" => {
            let key = hdkey_expr(&value, network)?;
            Ok(vec![AccountDescriptor { kind: "taproot".into(), descriptor: format!("tr({key}/<0;1>/*)") }])
        }
        other => Err(Error::Ur(format!("unsupported UR type '{other}'"))),
    }
}

/// crypto-account = { 1: master-fingerprint, 2: [ output-descriptor… ] }.
fn account_descriptors(v: &Value, net: notes_core::Network) -> Result<Vec<AccountDescriptor>, Error> {
    let map = as_map(v).ok_or_else(|| Error::Ur("account not a map".into()))?;
    let arr = map_get(map, 2)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Ur("account has no output-descriptors".into()))?;
    Ok(arr.iter().filter_map(|d| output_descriptor(d, net)).collect())
}

/// One output descriptor, either the newer text-`source` map or the old tagged
/// (script-type wrapping a crypto-hdkey) form. `None` for unsupported types.
fn output_descriptor(v: &Value, net: notes_core::Network) -> Option<AccountDescriptor> {
    // Newer form: a map carrying the descriptor as text under key 1.
    if let Some(map) = as_map(v) {
        if let Some(Value::Text(src)) = map_get(map, 1) {
            let d = src.split('#').next().unwrap_or(src).trim().to_string();
            let kind = if d.starts_with("tr(") {
                "taproot"
            } else if d.starts_with("wpkh(") {
                "segwit"
            } else {
                return None;
            };
            return Some(AccountDescriptor { kind: kind.into(), descriptor: d });
        }
    }
    // Old tagged form: outer script-type tag → hdkey.
    let (kind, prefix) = script_kind(v)?;
    let hd = innermost_hdkey(v)?;
    let key = hdkey_expr(hd, net).ok()?;
    Some(AccountDescriptor { kind: kind.into(), descriptor: format!("{prefix}({key}/<0;1>/*)") })
}

fn script_kind(v: &Value) -> Option<(&'static str, &'static str)> {
    match v {
        Value::Tag(t, _) if *t == TAG_TR => Some(("taproot", "tr")),
        Value::Tag(t, _) if *t == TAG_WPKH => Some(("segwit", "wpkh")),
        _ => None,
    }
}

/// Walk script-type tags down to the crypto-hdkey map.
fn innermost_hdkey(v: &Value) -> Option<&Value> {
    match v {
        Value::Tag(t, inner) if *t == TAG_HDKEY => Some(inner),
        Value::Tag(_, inner) => innermost_hdkey(inner),
        Value::Map(_) => Some(v),
        _ => None,
    }
}

/// crypto-hdkey → key expression `[fingerprint/path]xpub` (reconstructs the
/// base58 xpub from key-data + chain-code + origin).
fn hdkey_expr(v: &Value, net: notes_core::Network) -> Result<String, Error> {
    let map = as_map(v).ok_or_else(|| Error::Ur("hdkey not a map".into()))?;
    let key_data = get_bytes(map, 3).ok_or_else(|| Error::Ur("hdkey: no key-data".into()))?;
    let chain_code = get_bytes(map, 4).ok_or_else(|| Error::Ur("hdkey: no chain-code".into()))?;
    let parent_fp = get_uint(map, 8).unwrap_or(0) as u32;

    let (path, src_fp, depth, last_child) = match map_get(map, 6) {
        Some(o) => keypath(o)?,
        None => (String::new(), 0u32, 0u8, ChildNumber::from_normal_idx(0).unwrap()),
    };

    let cc: [u8; 32] = chain_code
        .as_slice()
        .try_into()
        .map_err(|_| Error::Ur("hdkey: chain-code not 32 bytes".into()))?;
    let public_key =
        PublicKey::from_slice(&key_data).map_err(|e| Error::Ur(format!("hdkey: pubkey {e}")))?;

    let xpub = Xpub {
        network: net_kind(net),
        depth,
        parent_fingerprint: Fingerprint::from(parent_fp.to_be_bytes()),
        child_number: last_child,
        public_key,
        chain_code: ChainCode::from(cc),
    };

    Ok(if path.is_empty() {
        xpub.to_string()
    } else {
        format!("[{src_fp:08x}/{path}]{xpub}")
    })
}

/// crypto-keypath = { 1: components, 2: source-fingerprint, 3: depth }.
/// Returns (path string like "86h/0h/0h", source fingerprint, depth, last child).
fn keypath(v: &Value) -> Result<(String, u32, u8, ChildNumber), Error> {
    let map = as_map(v).ok_or_else(|| Error::Ur("keypath not a map".into()))?;
    let src_fp = get_uint(map, 2).unwrap_or(0) as u32;
    let comps = map_get(map, 1)
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Ur("keypath: no components".into()))?;

    let mut parts = Vec::new();
    let mut last = ChildNumber::from_normal_idx(0).unwrap();
    let mut i = 0;
    while i + 1 < comps.len() {
        let idx = comps[i].as_integer().and_then(|n| u32::try_from(n).ok());
        let hard = comps[i + 1].as_bool().unwrap_or(false);
        if let Some(n) = idx {
            parts.push(format!("{n}{}", if hard { "h" } else { "" }));
            last = if hard {
                ChildNumber::from_hardened_idx(n).unwrap_or(last)
            } else {
                ChildNumber::from_normal_idx(n).unwrap_or(last)
            };
        }
        i += 2;
    }
    let depth = get_uint(map, 3).map(|d| d as u8).unwrap_or(parts.len() as u8);
    Ok((parts.join("/"), src_fp, depth, last))
}

fn net_kind(net: notes_core::Network) -> NetworkKind {
    match net {
        notes_core::Network::Mainnet => NetworkKind::Main,
        _ => NetworkKind::Test,
    }
}

// ---- CBOR map helpers ----

fn as_map(v: &Value) -> Option<&Vec<(Value, Value)>> {
    v.as_map()
}

fn map_get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter().find_map(|(k, val)| {
        k.as_integer().map(i128::from).filter(|&i| i == key).map(|_| val)
    })
}

fn get_bytes(map: &[(Value, Value)], key: i128) -> Option<Vec<u8>> {
    map_get(map, key).and_then(Value::as_bytes).cloned()
}

fn get_uint(map: &[(Value, Value)], key: i128) -> Option<u64> {
    map_get(map, key).and_then(Value::as_integer).and_then(|i: Integer| u64::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use notes_core::Network;

    // Build a crypto-hdkey CBOR map for an account xpub (BIP-86 test vector),
    // wrapped as tr() inside a crypto-account, then assert it decodes to the
    // expected multipath descriptor.
    fn hdkey_value() -> Value {
        // A valid compressed secp256k1 pubkey (the generator point) + any chain
        // code — enough to reconstruct a well-formed xpub for the assertion.
        let key_data =
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        // Origin m/86'/0'/0' with source fingerprint 0x12345678.
        let origin = Value::Map(vec![
            (Value::from(1u64), Value::Array(vec![
                Value::from(86u64), Value::Bool(true),
                Value::from(0u64), Value::Bool(true),
                Value::from(0u64), Value::Bool(true),
            ])),
            (Value::from(2u64), Value::from(0x1234_5678u64)),
            (Value::from(3u64), Value::from(3u64)),
        ]);
        Value::Map(vec![
            (Value::from(3u64), Value::Bytes(key_data)),
            (Value::from(4u64), Value::Bytes(vec![0x11u8; 32])),
            (Value::from(6u64), origin),
            (Value::from(8u64), Value::from(0xabcd_ef01u64)),
        ])
    }

    #[test]
    fn decodes_tagged_taproot_account() {
        // crypto-account { 1: mfp, 2: [ tr( hdkey ) ] }
        let tr = Value::Tag(TAG_TR, Box::new(Value::Tag(TAG_HDKEY, Box::new(hdkey_value()))));
        let account = Value::Map(vec![
            (Value::from(1u64), Value::from(0x1234_5678u64)),
            (Value::from(2u64), Value::Array(vec![tr])),
        ]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&account, &mut cbor).unwrap();

        let descs = descriptors_from_ur("crypto-account", &cbor, Network::Mainnet).unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].kind, "taproot");
        let d = &descs[0].descriptor;
        assert!(d.starts_with("tr([12345678/86h/0h/0h]xpub"), "got {d}");
        assert!(d.ends_with("/<0;1>/*)"), "got {d}");
    }

    #[test]
    fn decodes_new_text_output_descriptor() {
        // Newer output-descriptor: a map with the descriptor text under key 1.
        let od = Value::Map(vec![(
            Value::from(1u64),
            Value::Text("wpkh([abcdef01/84h/1h/0h]tpubDkey/<0;1>/*)#checksum".into()),
        )]);
        let mut cbor = Vec::new();
        ciborium::into_writer(&od, &mut cbor).unwrap();
        let descs = descriptors_from_ur("crypto-output-descriptor", &cbor, Network::Testnet4).unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].kind, "segwit");
        assert_eq!(descs[0].descriptor, "wpkh([abcdef01/84h/1h/0h]tpubDkey/<0;1>/*)");
    }
}
