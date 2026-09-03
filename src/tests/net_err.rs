use crate::*;

#[test]
fn rate_limit_becomes_a_calm_retry_message() {
    let raw = "http: 429 Too Many Requests: <html><body>rate limited</body></html>";
    assert_eq!(friendly_net_err(raw), "server is busy — retrying shortly");
    // app-core's trim_error_body format (no reason phrase) matches too.
    assert_eq!(friendly_net_err("http: 429: Too Many Requests"), "server is busy — retrying shortly");
    assert_eq!(friendly_net_err("429: Too Many Requests"), "server is busy — retrying shortly");
}

#[test]
fn a_429_sat_amount_in_a_rejection_is_not_a_rate_limit() {
    // "429" as a literal fee value must pass through as the real
    // rejection, not become a misleading "server is busy".
    let raw = "http: 400: sendrawtransaction min relay fee not met, 429 < 1000";
    assert_eq!(friendly_net_err(raw), raw);
}

#[test]
fn html_bodies_are_stripped_and_whitespace_collapsed() {
    let raw = "http: 500 Internal Server Error:  \n  <html>\n<body>boom</body></html>";
    assert_eq!(friendly_net_err(raw), "http: 500 Internal Server Error:");
}

#[test]
fn short_plain_errors_pass_through_untouched() {
    assert_eq!(friendly_net_err("connection reset"), "connection reset");
}

#[test]
fn very_long_errors_are_capped() {
    let raw = "e".repeat(200);
    let out = friendly_net_err(&raw);
    assert_eq!(out.chars().count(), 123); // 120 + "..."
    assert!(out.ends_with("..."));
}
