//! Mac camera glue: AVFoundation via nokhwa → grayscale frames → rqrr.
//! Behind the CameraSource idea from the PLAN — iOS/Android backends
//! slot in at phase 4. First open triggers the macOS TCC camera prompt
//! (bundled app: NSCameraUsageDescription via scripts/bundle-mac.sh).

use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::Camera;

/// Capture frames for up to `seconds`, trying to QR-decode each one.
/// Returns the first decoded payload (as bytes), or None on timeout.
/// `progress` gets (frames_seen, width, height) once per second.
pub fn capture_and_decode(
    seconds: u64,
    mut progress: impl FnMut(u64, u32, u32),
) -> Result<Option<Vec<u8>>, String> {
    let format = RequestedFormat::new::<LumaFormat>(RequestedFormatType::AbsoluteHighestResolution);
    let mut cam = Camera::new(CameraIndex::Index(0), format).map_err(|e| e.to_string())?;
    cam.open_stream().map_err(|e| e.to_string())?;

    let start = std::time::Instant::now();
    let mut frames = 0u64;
    let mut last_tick = 0u64;
    while start.elapsed().as_secs() < seconds {
        let frame = cam.frame().map_err(|e| e.to_string())?;
        let gray = frame.decode_image::<LumaFormat>().map_err(|e| e.to_string())?;
        frames += 1;
        let (w, h) = (gray.width(), gray.height());
        let tick = start.elapsed().as_secs();
        if tick > last_tick {
            last_tick = tick;
            progress(frames, w, h);
        }
        let raw = gray.into_raw();
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(
            w as usize,
            h as usize,
            |x, y| raw[y * w as usize + x],
        );
        for grid in prepared.detect_grids() {
            let mut payload = Vec::new();
            if grid.decode_to(&mut payload).is_ok() {
                let _ = cam.stop_stream();
                return Ok(Some(payload));
            }
        }
    }
    let _ = cam.stop_stream();
    Ok(None)
}

/// Headless spike: open the camera (TCC prompt on first run), report
/// frame flow, decode whatever QR is held up to it.
pub fn spike(seconds: u64) -> Result<(), String> {
    println!("cb: spike-camera open=try (hold any QR up to the webcam)");
    let decoded = capture_and_decode(seconds, |frames, w, h| {
        println!("cb: spike-camera frames={frames} res={w}x{h}");
    })?;
    match decoded {
        Some(payload) => {
            println!(
                "cb: spike-camera decode=ok bytes={} utf8={}",
                payload.len(),
                String::from_utf8_lossy(&payload)
            );
            Ok(())
        }
        None => {
            println!("cb: spike-camera decode=timeout (frames flowed — capture path OK)");
            Ok(())
        }
    }
}
