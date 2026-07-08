//! Animated `crypto-psbt` UR (BCR-2020-006) framing for QR export/import.
//!
//! Uses `foundation-ur` — the exact multipart-UR codec the KeyOS system QR
//! scanner runs — so frames we render are byte-for-byte reassemblable by the
//! Prime app (and, being spec `crypto-psbt`, by Sparrow etc.). A
//! `crypto-psbt` is CBOR-identical to the `bytes` type (a single byte string),
//! so the payload is the raw serialized PSBT.

use foundation_ur::{Decoder, Encoder, UR};

use crate::Error;

/// The UR type for a PSBT (BCR-2020-006).
pub const PSBT_UR_TYPE: &str = "crypto-psbt";

/// Encode serialized PSBT bytes into animated UR fragments — one per QR frame.
/// `max_fragment` bounds each fragment's payload size (tune to QR capacity).
/// A small PSBT yields a single fragment (`ur:crypto-psbt/<bytewords>`); a
/// large one yields a `ur:crypto-psbt/<i>-<n>/…` sequence.
pub fn encode_psbt(psbt_bytes: &[u8], max_fragment: usize) -> Vec<String> {
    let mut enc = Encoder::new();
    enc.start(PSBT_UR_TYPE, psbt_bytes, max_fragment.max(1));
    let n = enc.sequence_count();
    (0..n).map(|_| enc.next_part().to_string()).collect()
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
        self.inner
            .message()
            .map_err(|e| Error::Ur(format!("message: {e:?}")))?
            .map(<[u8]>::to_vec)
            .ok_or_else(|| Error::Ur("no message".into()))
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
