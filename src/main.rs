//! M5 shell: Slint window wired to app-core, plus headless spike modes.
//!
//!   chain-notes-app --spike keychain      # secret round-trip, no UI
//!   chain-notes-app --spike camera [secs] # TCC prompt + QR decode
//!   APP_KEY=<material> [APP_NETWORK=testnet4] chain-notes-app
//!
//! Real screens (onboarding/notes/compose/settings) land at M6.

mod camera;
mod keychain;
mod qr;

use app_core::identity::{parse_key_material, realize};
use app_core::notes_core::Network;
use slint::ComponentHandle;

slint::include_modules!();

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--spike") {
        let result = match args.get(2).map(String::as_str) {
            Some("keychain") => keychain::spike(),
            Some("camera") => {
                let secs = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(15);
                camera::spike(secs)
            }
            other => Err(format!("unknown spike {other:?} (keychain|camera)")),
        };
        if let Err(e) = result {
            eprintln!("cb: spike err={e}");
            std::process::exit(1);
        }
        return;
    }

    let window = AppWindow::new().expect("window");

    // Identity from APP_KEY (env) until M6 onboarding exists.
    let network = std::env::var("APP_NETWORK")
        .ok()
        .and_then(|s| Network::from_str_opt(&s))
        .unwrap_or(Network::Testnet4);
    if let Ok(key) = std::env::var("APP_KEY") {
        match parse_key_material(&key, network).and_then(|m| realize(&m, network)) {
            Ok(ident) => {
                println!("cb: identity kind={} network={} address={}", ident.kind, network.as_str(), ident.address);
                window.set_status(format!("{} identity · {}", ident.kind, network.as_str()).into());
                window.set_address(ident.address.as_str().into());
                if let Some(img) = qr::qr_image(&ident.address.to_uppercase()) {
                    window.set_address_qr(img);
                }
            }
            Err(e) => window.set_status(format!("APP_KEY error: {e}").into()),
        }
    }

    let weak = window.as_weak();
    window.on_spike_camera(move || {
        let weak = weak.clone();
        std::thread::spawn(move || {
            let line = match camera::capture_and_decode(15, |_, _, _| {}) {
                Ok(Some(p)) => format!(
                    "camera: decoded {} bytes: {}",
                    p.len(),
                    String::from_utf8_lossy(&p)
                ),
                Ok(None) => "camera: frames OK, no QR seen in 15s".to_string(),
                Err(e) => format!("camera: {e}"),
            };
            println!("cb: spike-camera-ui {line}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_spike_log(line.into());
                }
            });
        });
    });

    let weak = window.as_weak();
    window.on_spike_keychain(move || {
        let weak = weak.clone();
        std::thread::spawn(move || {
            let line = match keychain::spike() {
                Ok(()) => "keychain: roundtrip ok".to_string(),
                Err(e) => format!("keychain: {e}"),
            };
            println!("cb: spike-keychain-ui {line}");
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(w) = weak.upgrade() {
                    w.set_spike_log(line.into());
                }
            });
        });
    });

    window.run().expect("event loop");
}
