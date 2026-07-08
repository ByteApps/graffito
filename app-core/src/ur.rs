//! Animated `crypto-psbt` UR (BCR-2020-006) framing for QR export/import.
//!
//! Uses `foundation-ur` — the exact multipart-UR codec the KeyOS system QR
//! scanner runs — so frames we render are byte-for-byte reassemblable by the
//! Prime app (and, being spec `crypto-psbt`, by Sparrow etc.).
//!
//! Per BCR-2020-006 a `crypto-psbt` UR message is a **CBOR byte string** that
//! wraps the serialized PSBT — NOT the raw PSBT bytes. `foundation-ur` is a
//! raw-payload codec (it byteword-encodes whatever bytes it's given, no CBOR
//! layer), so we add/remove that CBOR bstr wrapper ourselves. This is exactly
//! what the Passport firmware does on both sides (`minicbor` ByteVec on export,
//! `UrValue::from_ur` on import — verified in gui-app-bitcoin), so our QRs
//! interoperate with the stock Bitcoin Wallet and other UR wallets.

use ciborium::value::Value;
use foundation_ur::{Decoder, Encoder, UR};

use crate::Error;

/// The UR type for a PSBT (BCR-2020-006).
pub const PSBT_UR_TYPE: &str = "crypto-psbt";

/// Encode serialized PSBT bytes into animated UR fragments — one per QR frame.
/// `max_fragment` bounds each fragment's payload size (tune to QR capacity).
/// A small PSBT yields a single fragment (`ur:crypto-psbt/<bytewords>`); a
/// large one yields a `ur:crypto-psbt/<i>-<n>/…` sequence.
pub fn encode_psbt(psbt_bytes: &[u8], max_fragment: usize) -> Vec<String> {
    // crypto-psbt = a CBOR byte string wrapping the serialized PSBT.
    let mut cbor = Vec::with_capacity(psbt_bytes.len() + 5);
    ciborium::into_writer(&Value::Bytes(psbt_bytes.to_vec()), &mut cbor).expect("cbor bstr");
    encode_ur(PSBT_UR_TYPE, &cbor, max_fragment)
}

/// Frame an already-encoded UR payload (raw CBOR) into animated UR parts — one
/// per QR frame. Used to emit `crypto-account`/`crypto-output-descriptor`/
/// `crypto-hdkey` test QRs whose CBOR the caller built.
pub fn encode_ur(ur_type: &str, payload: &[u8], max_fragment: usize) -> Vec<String> {
    let mut enc = Encoder::new();
    enc.start(ur_type, payload, max_fragment.max(1));
    let n = enc.sequence_count();
    (0..n).map(|_| enc.next_part().to_string()).collect()
}

/// Unwrap a `crypto-psbt` UR message (a CBOR byte string) to the serialized
/// PSBT. Tolerates an already-unwrapped (raw) message for backward-compat.
fn unwrap_crypto_psbt(msg: Vec<u8>) -> Vec<u8> {
    if msg.starts_with(b"psbt\xff") {
        return msg; // raw PSBT, not CBOR-wrapped
    }
    match ciborium::from_reader::<Value, _>(msg.as_slice()) {
        Ok(Value::Bytes(b)) => b,
        _ => msg,
    }
}

/// Decode a UR string (one part, or whitespace/newline-separated multi-part)
/// into its type and reassembled CBOR message bytes. Used to dispatch account
/// exports (`crypto-account`, `crypto-output-descriptor`, `crypto-hdkey`).
pub fn decode_ur_string(s: &str) -> Result<(String, Vec<u8>), Error> {
    let mut dec = Decoder::default();
    for part in s.split_whitespace() {
        let lo = part.to_lowercase();
        if !lo.starts_with("ur:") {
            continue;
        }
        let ur = UR::parse(&lo).map_err(|e| Error::Ur(format!("parse: {e:?}")))?;
        dec.receive(ur).map_err(|e| Error::Ur(format!("receive: {e:?}")))?;
        if dec.is_complete() {
            break;
        }
    }
    if !dec.is_complete() {
        return Err(Error::Ur("incomplete UR (scan all frames)".into()));
    }
    let ty = dec.ur_type().ok_or_else(|| Error::Ur("no UR type".into()))?.to_string();
    let msg = dec
        .message()
        .map_err(|e| Error::Ur(format!("message: {e:?}")))?
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Ur("no message".into()))?;
    Ok((ty, msg))
}

/// Incrementally reassembles `crypto-psbt` UR fragments scanned from QR frames.
#[derive(Default)]
pub struct PsbtUrDecoder {
    inner: Decoder,
}

impl PsbtUrDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one scanned UR string (case-insensitive). Returns `true` once the
    /// whole sequence has been reassembled. Non-UR / foreign-type strings and
    /// malformed parts return `Err` so the caller can keep scanning.
    pub fn receive(&mut self, part: &str) -> Result<bool, Error> {
        let lowered = part.trim().to_lowercase();
        if !lowered.starts_with("ur:") {
            return Err(Error::Ur("not a UR string".into()));
        }
        let ur = UR::parse(&lowered).map_err(|e| Error::Ur(format!("parse: {e:?}")))?;
        self.inner.receive(ur).map_err(|e| Error::Ur(format!("receive: {e:?}")))?;
        Ok(self.inner.is_complete())
    }

    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    /// Fraction reassembled so far, for a progress indicator (0.0..=1.0).
    pub fn progress(&self) -> f32 {
        self.inner.estimated_percent_complete() as f32 / 100.0
    }

    /// The reassembled PSBT bytes, once complete. Errors if the sequence is
    /// incomplete or carries a non-`crypto-psbt` UR type.
    pub fn psbt_bytes(&self) -> Result<Vec<u8>, Error> {
        if !self.inner.is_complete() {
            return Err(Error::Ur("sequence incomplete".into()));
        }
        match self.inner.ur_type() {
            Some(t) if t == PSBT_UR_TYPE => {}
            Some(t) => return Err(Error::Ur(format!("UR type {t}, expected crypto-psbt"))),
            None => return Err(Error::Ur("no UR type".into())),
        }
        let msg = self
            .inner
            .message()
            .map_err(|e| Error::Ur(format!("message: {e:?}")))?
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::Ur("no message".into()))?;
        Ok(unwrap_crypto_psbt(msg))
    }
}

/// Type-agnostic incremental UR reassembler — feed scanned frame strings until
/// complete, for animated account exports (`crypto-account` etc.) that span
/// several QR frames. Get the type + bytes with [`Self::message`].
#[derive(Default)]
pub struct UrDecoder {
    inner: Decoder,
}

impl UrDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one scanned UR string; returns `true` once fully reassembled.
    /// Non-UR / malformed frames return `Err` so the caller keeps scanning.
    pub fn receive(&mut self, part: &str) -> Result<bool, Error> {
        let lo = part.trim().to_lowercase();
        if !lo.starts_with("ur:") {
            return Err(Error::Ur("not a UR string".into()));
        }
        let ur = UR::parse(&lo).map_err(|e| Error::Ur(format!("parse: {e:?}")))?;
        self.inner.receive(ur).map_err(|e| Error::Ur(format!("receive: {e:?}")))?;
        Ok(self.inner.is_complete())
    }

    pub fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(bytes: &[u8], frag: usize) {
        let frames = encode_psbt(bytes, frag);
        assert!(!frames.is_empty());
        assert!(frames.iter().all(|f| f.to_lowercase().starts_with("ur:crypto-psbt/")));
        let mut dec = PsbtUrDecoder::new();
        let mut done = false;
        for f in &frames {
            done = dec.receive(f).unwrap();
            if done {
                break;
            }
        }
        assert!(done && dec.is_complete());
        assert_eq!(dec.psbt_bytes().unwrap(), bytes);
    }

    #[test]
    fn crypto_psbt_message_is_cbor_wrapped() {
        // Interop contract with the Passport (and Sparrow etc.): the on-wire
        // UR message is a CBOR byte string wrapping the PSBT (BCR-2020-006), the
        // shape `UrValue::from_ur("crypto-psbt", ..)` decodes — not the raw PSBT.
        let psbt = b"psbt\xff\x01\x02\x03";
        let frames = encode_psbt(psbt, 400);
        let (ty, msg) = decode_ur_string(&frames.join(" ")).unwrap();
        assert_eq!(ty, "crypto-psbt");
        match ciborium::from_reader::<Value, _>(msg.as_slice()).unwrap() {
            Value::Bytes(b) => assert_eq!(b, psbt),
            other => panic!("expected CBOR bstr, got {other:?}"),
        }
    }

    #[test]
    fn tolerates_unwrapped_legacy_message() {
        // A raw (non-CBOR) PSBT message still decodes, for backward-compat.
        let psbt = b"psbt\xff\xaa\xbb".to_vec();
        assert_eq!(unwrap_crypto_psbt(psbt.clone()), psbt);
    }

    #[test]
    fn single_and_multi_frame_roundtrip() {
        // Small payload → single frame.
        roundtrip(&[0x70, 0x73, 0x62, 0x74, 0xff, 1, 2, 3, 4], 200);
        // Larger payload with a small fragment size → animated multi-frame.
        let big: Vec<u8> = (0..600u32).map(|i| (i * 7 % 251) as u8).collect();
        let frames = encode_psbt(&big, 50);
        assert!(frames.len() > 1, "expected an animated sequence");
        roundtrip(&big, 50);
    }

    #[test]
    fn rejects_non_ur_and_incomplete() {
        let mut dec = PsbtUrDecoder::new();
        assert!(dec.receive("hello").is_err());
        assert!(dec.psbt_bytes().is_err()); // nothing received yet
    }
}
