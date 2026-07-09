//! iOS camera backend: AVCaptureSession + AVCaptureVideoDataOutput. An objc2
//! delegate copies each frame's Y (luma) plane over a channel; `capture_frames`
//! drains it, pushing a downscaled RGBA preview and feeding decoded QR payloads
//! to `feed` — matching the macOS (nokhwa) backend's API.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass};
use objc2_av_foundation::{
    AVAuthorizationStatus, AVCaptureConnection, AVCaptureDevice, AVCaptureDeviceInput,
    AVCaptureOutput, AVCaptureSession, AVCaptureVideoDataOutput,
    AVCaptureVideoDataOutputSampleBufferDelegate, AVMediaTypeVideo,
};
use objc2_core_media::CMSampleBufferGetImageBuffer;
use objc2_core_video::{
    CVPixelBufferGetBaseAddressOfPlane, CVPixelBufferGetBytesPerRowOfPlane,
    CVPixelBufferGetHeightOfPlane, CVPixelBufferGetWidthOfPlane, CVPixelBufferLockBaseAddress,
    CVPixelBufferUnlockBaseAddress, CVPixelBufferLockFlags,
};

type Frame = (Vec<u8>, u32, u32); // tightly-packed luma, width, height

struct Ivars {
    tx: Sender<Frame>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "CNCameraDelegate"]
    #[ivars = Ivars]
    struct Delegate;

    unsafe impl NSObjectProtocol for Delegate {}

    unsafe impl AVCaptureVideoDataOutputSampleBufferDelegate for Delegate {
        #[unsafe(method(captureOutput:didOutputSampleBuffer:fromConnection:))]
        unsafe fn did_output(
            &self,
            _output: &AVCaptureOutput,
            sample_buffer: &objc2_core_media::CMSampleBuffer,
            _conn: &AVCaptureConnection,
        ) {
            let Some(pb) = CMSampleBufferGetImageBuffer(sample_buffer) else {
                return;
            };
            let flags = CVPixelBufferLockFlags::ReadOnly;
            if CVPixelBufferLockBaseAddress(&pb, flags) != 0 {
                return;
            }
            let w = CVPixelBufferGetWidthOfPlane(&pb, 0);
            let h = CVPixelBufferGetHeightOfPlane(&pb, 0);
            let stride = CVPixelBufferGetBytesPerRowOfPlane(&pb, 0);
            let base = CVPixelBufferGetBaseAddressOfPlane(&pb, 0);
            if !base.is_null() && w > 0 && h > 0 && stride >= w {
                let mut luma = vec![0u8; w * h];
                let src = base as *const u8;
                for y in 0..h {
                    std::ptr::copy_nonoverlapping(
                        src.add(y * stride),
                        luma.as_mut_ptr().add(y * w),
                        w,
                    );
                }
                let _ = self.ivars().tx.send((luma, w as u32, h as u32));
            }
            CVPixelBufferUnlockBaseAddress(&pb, flags);
        }
    }
);

impl Delegate {
    fn new(tx: Sender<Frame>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(Ivars { tx });
        unsafe { msg_send![super(this), init] }
    }
}

/// Block until the user answers the camera-permission prompt. Returns false if
/// denied. Authorized status returns immediately.
fn ensure_authorized() -> bool {
    let media = unsafe { AVMediaTypeVideo }.expect("AVMediaTypeVideo");
    match unsafe { AVCaptureDevice::authorizationStatusForMediaType(media) } {
        AVAuthorizationStatus::Authorized => true,
        AVAuthorizationStatus::Denied | AVAuthorizationStatus::Restricted => false,
        _ => {
            let (tx, rx) = std::sync::mpsc::channel();
            let block = RcBlock::new(move |granted: Bool| {
                let _ = tx.send(granted.as_bool());
            });
            unsafe {
                AVCaptureDevice::requestAccessForMediaType_completionHandler(media, &block);
            }
            rx.recv_timeout(Duration::from_secs(60)).unwrap_or(false)
        }
    }
}

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

fn build_session(tx: Sender<Frame>) -> Result<(Retained<AVCaptureSession>, Retained<Delegate>), String> {
    unsafe {
        let media = AVMediaTypeVideo.expect("AVMediaTypeVideo");
        let device = AVCaptureDevice::defaultDeviceWithMediaType(media)
            .ok_or_else(|| "no camera device".to_string())?;
        let input = AVCaptureDeviceInput::deviceInputWithDevice_error(&device)
            .map_err(|e| format!("camera input: {e}"))?;
        let session = AVCaptureSession::new();
        if session.canAddInput(&input) {
            session.addInput(&input);
        } else {
            return Err("cannot add camera input".into());
        }
        let output = AVCaptureVideoDataOutput::new();
        output.setAlwaysDiscardsLateVideoFrames(true);
        let delegate = Delegate::new(tx);
        let queue = dispatch2::DispatchQueue::new("cn.camera", None);
        output.setSampleBufferDelegate_queue(
            Some(ProtocolObject::from_ref(&*delegate)),
            Some(&queue),
        );
        if session.canAddOutput(&output) {
            session.addOutput(&output);
        } else {
            return Err("cannot add camera output".into());
        }
        session.startRunning();
        Ok((session, delegate))
    }
}

pub fn capture_frames(
    seconds: u64,
    cancel: &AtomicBool,
    mut preview: impl FnMut(&[u8], u32, u32),
    mut feed: impl FnMut(&[u8]) -> bool,
) -> Result<bool, String> {
    if !ensure_authorized() {
        return Err("camera permission denied".into());
    }
    let (tx, rx): (Sender<Frame>, Receiver<Frame>) = std::sync::mpsc::channel();
    let (session, _delegate) = build_session(tx)?;

    let start = Instant::now();
    let mut done = false;
    let mut frames = 0u64;
    while start.elapsed().as_secs() < seconds && !cancel.load(Ordering::Relaxed) {
        let (raw, w, h) = match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(f) => f,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => break,
        };
        let (wz, hz) = (w as usize, h as usize);
        frames += 1;

        let (rgba, pw, ph) = gray_to_rgba_scaled(&raw, wz, hz, 420);
        preview(&rgba, pw, ph);

        if frames % 2 == 0 {
            let mut prepared =
                rqrr::PreparedImage::prepare_from_greyscale(wz, hz, |x, y| raw[y * wz + x]);
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
    unsafe { session.stopRunning() };
    Ok(done)
}

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
