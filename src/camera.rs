//! Mac camera glue: AVFoundation via nokhwa → grayscale frames → rqrr, plus a
//! downscaled RGBA `preview` callback per frame so the UI can show a live view.
//! Behind the CameraSource idea from the PLAN — iOS/Android backends slot in at
//! phase 4. First open triggers the macOS TCC camera prompt (bundled app:
//! NSCameraUsageDescription via scripts/bundle-mac.sh).

use std::sync::atomic::{AtomicBool, Ordering};

use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType, Resolution};
use nokhwa::Camera;

/// Open the webcam capped at a modest resolution. AVFoundation reports no
/// enumerable formats (`compatible_camera_formats()` is empty), so we can't
/// down-set after the fact — instead we request a capped resolution at creation
/// and fall back down a ladder. ~720p decodes QRs fine and, unlike 1080p+ (which
/// crawls at ~2 fps decoding a full Luma frame each iteration), keeps the live
/// preview smooth.
fn open_capped_camera() -> Result<Camera, String> {
    let ladder = [
        RequestedFormatType::HighestResolution(Resolution::new(1280, 720)),
        RequestedFormatType::HighestResolution(Resolution::new(640, 480)),
        RequestedFormatType::AbsoluteHighestFrameRate,
        RequestedFormatType::AbsoluteHighestResolution,
    ];
    let mut last_err = String::from("no usable camera format");
    for rt in ladder {
        let fmt = RequestedFormat::new::<LumaFormat>(rt);
        match Camera::new(CameraIndex::Index(0), fmt) {
            Ok(mut cam) => match cam.open_stream() {
                Ok(()) => {
                    let r = cam.resolution();
                    eprintln!("cb: cam opened {}x{}", r.width(), r.height());
                    return Ok(cam);
                }
                Err(e) => last_err = e.to_string(),
            },
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(last_err)
}

/// Downscale a grayscale frame to RGBA (gray → R=G=B), longest side ≤ `maxdim` —
/// small enough to push through the UI event loop every frame as a live preview.
fn gray_to_rgba_scaled(raw: &[u8], w: usize, h: usize, maxdim: usize) -> (Vec<u8>, u32, u32) {
    let scale = ((w.max(h) as f32) / maxdim as f32).max(1.0);
    let ow = (((w as f32) / scale) as usize).max(1);
    let oh = (((h as f32) / scale) as usize).max(1);
    let mut out = vec![0u8; ow * oh * 4];
    for y in 0..oh {
        let row = ((y as f32) * scale) as usize * w;
        for x in 0..ow {
            let g = raw[row + ((x as f32) * scale) as usize];
            let o = (y * ow + x) * 4;
            out[o] = g;
            out[o + 1] = g;
            out[o + 2] = g;
            out[o + 3] = 255;
        }
    }
    (out, ow as u32, oh as u32)
}

/// Capture frames for up to `seconds` (or until `cancel` is set), pushing each
/// as a downscaled RGBA preview and feeding each decoded QR payload to `feed`.
/// Stops (returns `true`) when `feed` returns `true` — e.g. a single QR, or an
/// animated-UR sequence fully reassembled — else `false` on cancel/timeout.
pub fn capture_frames(
    seconds: u64,
    cancel: &AtomicBool,
    mut preview: impl FnMut(&[u8], u32, u32),
    mut feed: impl FnMut(&[u8]) -> bool,
) -> Result<bool, String> {
    let mut cam = open_capped_camera()?;

    let start = std::time::Instant::now();
    let mut done = false;
    let mut frames = 0u64;
    while start.elapsed().as_secs() < seconds && !cancel.load(Ordering::Relaxed) {
        let frame = match cam.frame() {
            Ok(f) => f,
            Err(e) => {
                eprintln!("cb: cam frame-err={e}");
                break;
            }
        };
        let gray = match frame.decode_image::<LumaFormat>() {
            Ok(g) => g,
            Err(e) => {
                eprintln!("cb: cam decode-err={e}");
                break;
            }
        };
        let (w, h) = (gray.width() as usize, gray.height() as usize);
        let raw = gray.into_raw();
        frames += 1;

        let (rgba, pw, ph) = gray_to_rgba_scaled(&raw, w, h, 420);
        preview(&rgba, pw, ph);

        // QR detection is the expensive step — run it every other frame so the
        // preview stays smooth (still ~15 scans/sec at 30 fps).
        if frames % 2 == 0 {
            let mut prepared =
                rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| raw[y * w + x]);
            for grid in prepared.detect_grids() {
                let mut payload = Vec::new();
                if grid.decode_to(&mut payload).is_ok() && feed(&payload) {
                    done = true;
                    break;
                }
            }
            if done {
                break;
            }
        }
    }
    let _ = cam.stop_stream();
    Ok(done)
}

/// Single-shot: capture (with preview) until one QR decodes, or cancel/timeout.
/// Returns its payload. Wraps [`capture_frames`] with a first-hit feed.
pub fn capture_and_decode(
    seconds: u64,
    cancel: &AtomicBool,
    preview: impl FnMut(&[u8], u32, u32),
) -> Result<Option<Vec<u8>>, String> {
    let mut out = None;
    capture_frames(seconds, cancel, preview, |p| {
        out = Some(p.to_vec());
        true
    })?;
    Ok(out)
}

/// Headless spike: open the camera (TCC prompt on first run), decode whatever QR
/// is held up to it.
pub fn spike(seconds: u64) -> Result<(), String> {
    println!("cb: spike-camera open=try (hold any QR up to the webcam)");
    let never = AtomicBool::new(false);
    match capture_and_decode(seconds, &never, |_, _, _| {})? {
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
