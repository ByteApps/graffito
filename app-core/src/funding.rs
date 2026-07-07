//! External funding wallet (watch-only) for paying a note tx with someone
//! else's coins via PSBT. The user supplies an OUTPUT DESCRIPTOR (or a bare
//! xpub, taken as taproot BIP-86) — not a private key — so the app can:
//!   * derive receive/change addresses,
//!   * scan them for spendable UTXOs (coin control), and
//!   * later (psbt_build.rs) populate BIP-32 / taproot key origins in the
//!     PSBT so a hardware wallet can recognise and sign its own inputs.
//!
//! Only single-sig `tr(...)` and `wpkh(...)` are accepted in v1 (the two
//! address types the plan supports; `tr` is also what the Prime test-signer
//! and notes-core's sighash handle).

use std::str::FromStr;

use miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derive::btc_network;
use crate::Error;

/// A saved external funding wallet (watch-only), persisted device-level so the
/// same hardware/software wallet can fund notes across identities and sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundingWallet {
    /// Stable key = first 8 bytes of SHA-256(descriptor), for dedup + row ids.
    pub id: String,
    pub label: String,
    /// The descriptor (or bare xpub) string exactly as imported; re-parsed
    /// with `source()`.
    pub descriptor: String,
    /// "taproot" | "segwit".
    pub kind: String,
    /// Cached from the last scan (for the list display; coins are re-scanned
    /// fresh when the wallet is actually used).
    #[serde(default)]
    pub balance: u64,
    #[serde(default)]
    pub coins: usize,
    #[serde(default)]
    pub scanned: bool,
}

impl FundingWallet {
    /// Validate an imported descriptor/xpub and build a saved wallet. A blank
    /// `label` gets a default (`taproot · bc1p…`).
    pub fn create(input: &str, label: &str, network: notes_core::Network) -> Result<Self, Error> {
        let descriptor = input.trim().to_string();
        let src = FundingSource::parse(&descriptor, network)?;
        let mut id = String::new();
        for b in &Sha256::digest(descriptor.as_bytes())[..8] {
            id.push_str(&format!("{b:02x}"));
        }
        let label = if label.trim().is_empty() {
            let addr0 = src.derive(0, 0).map(|d| d.address).unwrap_or_default();
            let short = if addr0.len() > 16 { format!("{}…", &addr0[..12]) } else { addr0 };
            format!("{} · {short}", src.kind.label())
        } else {
            label.trim().to_string()
        };
        Ok(FundingWallet { id, label, descriptor, kind: src.kind.label().into(), balance: 0, coins: 0, scanned: false })
    }

    /// Re-parse the stored descriptor into a live `FundingSource`.
    pub fn source(&self, network: notes_core::Network) -> Result<FundingSource, Error> {
        FundingSource::parse(&self.descriptor, network)
    }
}

/// Address type of a funding descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingKind {
    /// P2TR key-path — `tr(...)`. Signable by the Prime app and taproot HWWs.
    Taproot,
    /// P2WPKH (segwit v0) — `wpkh(...)`.
    Wpkh,
}

impl FundingKind {
    pub fn label(self) -> &'static str {
        match self {
            FundingKind::Taproot => "taproot",
            FundingKind::Wpkh => "segwit",
        }
    }
}

/// A parsed funding source: separate receive (`.../0/*`) and change
/// (`.../1/*`) descriptor chains, ready to derive addresses from.
#[derive(Debug, Clone)]
pub struct FundingSource {
    receive: Descriptor<DescriptorPublicKey>,
    change: Descriptor<DescriptorPublicKey>,
    pub kind: FundingKind,
    pub network: notes_core::Network,
}

/// One derived address of a funding source.
#[derive(Debug, Clone)]
pub struct DerivedAddr {
    /// 0 = receive chain, 1 = change chain.
    pub chain: usize,
    pub index: u32,
    pub address: String,
    pub spk: Vec<u8>,
}

/// A spendable UTXO discovered while scanning a funding source, tagged with
/// the derivation (chain/index) needed later to populate its PSBT input.
#[derive(Debug, Clone)]
pub struct FundingUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub address: String,
    pub chain: usize,
    pub index: u32,
    pub confirmed: bool,
}

/// Result of scanning a funding source: its spendable coins plus the first
/// unused change index (where a new change output should go).
#[derive(Debug, Clone)]
pub struct FundingScan {
    pub utxos: Vec<FundingUtxo>,
    pub next_change_index: u32,
}

impl FundingSource {
    /// Parse an output descriptor or bare xpub. Accepts:
    ///   * a multipath descriptor `tr(<key>/<0;1>/*)` (hardware-wallet export),
    ///   * a single-chain descriptor `tr(<key>/0/*)` (change reuses it), or
    ///   * a bare `xpub…`/`tpub…` (wrapped as taproot BIP-86 `tr(<xpub>/<0;1>/*)`).
    /// Key origins `[fingerprint/path]` are preserved when present.
    pub fn parse(input: &str, network: notes_core::Network) -> Result<Self, Error> {
        let s = input.trim();
        let desc_str = if is_bare_xpub(s) { format!("tr({s}/<0;1>/*)") } else { s.to_string() };

        let desc = Descriptor::<DescriptorPublicKey>::from_str(&desc_str)
            .map_err(|e| Error::Funding(format!("bad descriptor: {e}")))?;

        let kind = match desc.desc_type() {
            DescriptorType::Tr => FundingKind::Taproot,
            DescriptorType::Wpkh => FundingKind::Wpkh,
            other => {
                return Err(Error::Funding(format!(
                    "unsupported descriptor type {other:?} (only tr and wpkh)"
                )))
            }
        };

        let chains: Vec<Descriptor<DescriptorPublicKey>> = if desc.is_multipath() {
            desc.into_single_descriptors()
                .map_err(|e| Error::Funding(format!("multipath split: {e}")))?
        } else {
            vec![desc]
        };
        let receive = chains.first().cloned().ok_or(Error::Funding("empty descriptor".into()))?;
        let change = chains.get(1).cloned().unwrap_or_else(|| receive.clone());

        Ok(FundingSource { receive, change, kind, network })
    }

    fn chain(&self, i: usize) -> &Descriptor<DescriptorPublicKey> {
        if i == 0 {
            &self.receive
        } else {
            &self.change
        }
    }

    /// Whether the chains carry a `*` wildcard (ranged). A fixed descriptor
    /// (single key, no wildcard) only has index 0.
    pub fn is_ranged(&self) -> bool {
        self.receive.has_wildcard()
    }

    /// Derive the address + scriptPubKey at (`chain`, `index`).
    pub fn derive(&self, chain: usize, index: u32) -> Result<DerivedAddr, Error> {
        let def = self
            .chain(chain)
            .at_derivation_index(index)
            .map_err(|e| Error::Funding(format!("derive {chain}/{index}: {e}")))?;
        let address = def
            .address(btc_network(self.network))
            .map_err(|e| Error::Funding(format!("address {chain}/{index}: {e}")))?;
        Ok(DerivedAddr { chain, index, address: address.to_string(), spk: def.script_pubkey().to_bytes() })
    }

    /// The definite (index-fixed) descriptor at (`chain`, `index`) — used by
    /// psbt_build.rs to populate a PSBT input's key-origin fields.
    pub fn definite(
        &self,
        chain: usize,
        index: u32,
    ) -> Result<Descriptor<miniscript::DefiniteDescriptorKey>, Error> {
        self.chain(chain)
            .at_derivation_index(index)
            .map_err(|e| Error::Funding(format!("derive {chain}/{index}: {e}")))
    }
}

fn is_bare_xpub(s: &str) -> bool {
    !s.contains('(')
        && ["xpub", "tpub", "ypub", "zpub", "vpub", "upub", "Ypub", "Zpub"]
            .iter()
            .any(|p| s.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notes_core::Network;

    // Official BIP-86 test vectors (mainnet, account m/86'/0'/0').
    const BIP86_ACCT_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    #[test]
    fn taproot_multipath_derives_bip86_vectors() {
        let desc = format!("tr({BIP86_ACCT_XPUB}/<0;1>/*)");
        let f = FundingSource::parse(&desc, Network::Mainnet).unwrap();
        assert_eq!(f.kind, FundingKind::Taproot);
        assert!(f.is_ranged());
        // m/86'/0'/0'/0/0, 0/1, and 1/0 — the published BIP-86 addresses.
        assert_eq!(
            f.derive(0, 0).unwrap().address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            f.derive(0, 1).unwrap().address,
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
        assert_eq!(
            f.derive(1, 0).unwrap().address,
            "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"
        );
    }

    #[test]
    fn bare_xpub_is_taken_as_taproot() {
        let f = FundingSource::parse(BIP86_ACCT_XPUB, Network::Mainnet).unwrap();
        assert_eq!(f.kind, FundingKind::Taproot);
        // Same first receive address as the explicit tr(...) descriptor.
        assert_eq!(
            f.derive(0, 0).unwrap().address,
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn wpkh_descriptor_is_segwit() {
        let desc = format!("wpkh({BIP86_ACCT_XPUB}/<0;1>/*)");
        let f = FundingSource::parse(&desc, Network::Mainnet).unwrap();
        assert_eq!(f.kind, FundingKind::Wpkh);
        assert!(f.derive(0, 0).unwrap().address.starts_with("bc1q"));
    }

    #[test]
    fn unsupported_and_garbage_rejected() {
        // Legacy P2PKH not supported.
        assert!(FundingSource::parse(&format!("pkh({BIP86_ACCT_XPUB}/0/*)"), Network::Mainnet).is_err());
        assert!(FundingSource::parse("not a descriptor", Network::Mainnet).is_err());
    }

    /// Canned esplora: one used receive address (0/0) with a single confirmed
    /// UTXO; every other derived address is unused/empty.
    struct MockTransport {
        used_addr: String,
    }
    impl crate::chain::Transport for MockTransport {
        fn get_text(&self, path: &str) -> Result<String, Error> {
            let for_used = path.contains(&self.used_addr);
            if path.contains("/utxo") {
                Ok(if for_used {
                    r#"[{"txid":"aa","vout":0,"value":50000,"status":{"confirmed":true,"block_height":100,"block_time":1}}]"#
                } else {
                    "[]"
                }
                .into())
            } else if path.contains("/txs/chain") {
                Ok("[]".into())
            } else if path.contains("/txs") {
                Ok(if for_used {
                    r#"[{"txid":"aa","vin":[],"vout":[],"status":{"confirmed":true,"block_height":100,"block_time":1}}]"#
                } else {
                    "[]"
                }
                .into())
            } else {
                Ok(String::new())
            }
        }
        fn post_text(&self, _path: &str, _body: String) -> Result<String, Error> {
            Ok(String::new())
        }
    }

    #[test]
    fn scan_collects_utxos_and_next_change() {
        let f = FundingSource::parse(&format!("tr({BIP86_ACCT_XPUB}/<0;1>/*)"), Network::Mainnet).unwrap();
        let used = f.derive(0, 0).unwrap().address;
        let client =
            crate::chain::ChainClient::new(MockTransport { used_addr: used }, Network::Mainnet);
        let scan = client.scan_funding(&f, 3).unwrap();
        assert_eq!(scan.utxos.len(), 1);
        assert_eq!(scan.utxos[0].value, 50_000);
        assert_eq!(scan.utxos[0].chain, 0);
        assert_eq!(scan.utxos[0].index, 0);
        assert!(scan.utxos[0].confirmed);
        assert_eq!(scan.next_change_index, 0);
    }
}
