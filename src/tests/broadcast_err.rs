use crate::*;

#[test]
fn transport_errors_become_a_friendly_host_message() {
    let e = "transport: error sending request for url (https://mempool.space/testnet4/api/tx)";
    assert_eq!(
        friendly_broadcast_err(e, "https://mempool.space/testnet4/api"),
        "network error reaching mempool.space — check your connection"
    );
}

#[test]
fn transport_errors_fall_back_when_base_url_is_unknown() {
    let e = "transport: connection reset";
    assert_eq!(
        friendly_broadcast_err(e, ""),
        "network error reaching your node — check your connection"
    );
}

#[test]
fn server_rejections_pass_through_untouched() {
    let e = "http: 400 Bad Request: bad-txns-in-belowout";
    assert_eq!(friendly_broadcast_err(e, "https://mempool.space/testnet4/api"), e);
}

#[test]
fn non_broadcast_errors_pass_through_untouched() {
    let e = "no signed PSBT";
    assert_eq!(friendly_broadcast_err(e, "https://mempool.space/api"), e);
}

/// U5 (plan §2.1/§2.4): the four common rejection categories must read
/// IDENTICALLY whether the raw text came from Core's short
/// `testmempoolaccept` reject-reason tokens or from a
/// `sendrawtransaction` RPC-error message forwarded verbatim — proving
/// the mapping is keyed on the CONDITION, not on which backend's exact
/// wording happened to arrive.
#[test]
fn already_broadcast_reads_identically_regardless_of_wording() {
    let core_testmempoolaccept = "http: 400: txn-already-known";
    let core_sendraw_rpc_error = "http: bitcoind [-27]: Transaction already in block chain";
    let esplora_like = "http: 400 Bad Request: already in mempool";
    let expected = "already broadcast — this transaction is already on the network";
    assert_eq!(friendly_broadcast_err(core_testmempoolaccept, "bitcoind+http://127.0.0.1:8332"), expected);
    assert_eq!(friendly_broadcast_err(core_sendraw_rpc_error, "bitcoind+http://127.0.0.1:8332"), expected);
    assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
}

#[test]
fn fee_too_low_reads_identically_regardless_of_wording() {
    let core = "http: 400: min relay fee not met, 300 < 1000";
    let esplora_like = "http: 400 Bad Request: insufficient fee, rejecting replacement";
    let expected = "fee too low — increase the fee and try again";
    assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
    assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
}

#[test]
fn missing_inputs_reads_identically_regardless_of_wording() {
    let core = "http: 400: bad-txns-inputs-missingorspent";
    let esplora_like = "http: 400 Bad Request: missing inputs";
    let expected = "inputs missing or already spent — this transaction can't be sent";
    assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
    assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
}

#[test]
fn non_final_reads_identically_regardless_of_wording() {
    let core = "http: 400: non-final";
    let esplora_like = "http: 400 Bad Request: transaction is not final";
    let expected = "not final yet — try again once its timelock has passed";
    assert_eq!(friendly_broadcast_err(core, "bitcoind+http://127.0.0.1:8332"), expected);
    assert_eq!(friendly_broadcast_err(esplora_like, "https://mempool.space/api"), expected);
}

/// The pre-existing 429-in-a-fee-body guard ([`friendly_net_err`]'s own
/// `a_429_sat_amount_in_a_rejection_is_not_a_rate_limit` test) must
/// stay intact through this new layer too: a literal "429" sat amount
/// inside a min-relay-fee rejection must land on the FEE message, never
/// the "server is busy" one — `map_broadcast_rejection` runs BEFORE
/// `friendly_net_err`'s 429 check ever sees this text.
#[test]
fn a_429_sat_amount_in_a_fee_rejection_still_maps_to_fee_too_low_not_rate_limit() {
    let e = "http: 400: sendrawtransaction min relay fee not met, 429 < 1000";
    assert_eq!(
        friendly_broadcast_err(e, "bitcoind+http://127.0.0.1:8332"),
        "fee too low — increase the fee and try again"
    );
}
