//! Android camera backend: NDK Camera2 → YUV_420_888 into an AImageReader,
//! poll the latest frame, hand its Y (luma) plane to rqrr. Hand-rolled FFI
//! (the `ndk` crate doesn't wrap Camera2). Matches the shared
//! `capture_frames`/`capture_and_decode` API (preview + feed callbacks,
//! cancel flag, timeout) so the app's scan flow is identical to macOS/iOS.
//! NDK libs linked in build.rs (camera2ndk/mediandk/android).

use std::ffi::c_void;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

#[allow(non_camel_case_types)]
mod ffi {
    use super::*;

    pub enum ACameraManager {}
    pub enum ACameraDevice {}
    pub enum ACameraCaptureSession {}
    pub enum ACaptureRequest {}
    pub enum ACameraOutputTarget {}
    pub enum ACaptureSessionOutput {}
    pub enum ACaptureSessionOutputContainer {}
    pub enum AImageReader {}
    pub enum AImage {}
    pub enum ANativeWindow {}

    #[repr(C)]
    pub struct ACameraIdList {
        pub num_cameras: c_int,
        pub camera_ids: *const *const c_char,
    }

    #[repr(C)]
    pub struct ACameraDevice_StateCallbacks {
        pub context: *mut c_void,
        pub on_disconnected: extern "C" fn(*mut c_void, *mut ACameraDevice),
        pub on_error: extern "C" fn(*mut c_void, *mut ACameraDevice, c_int),
    }

    #[repr(C)]
    pub struct ACameraCaptureSession_stateCallbacks {
        pub context: *mut c_void,
        pub on_closed: extern "C" fn(*mut c_void, *mut ACameraCaptureSession),
        pub on_ready: extern "C" fn(*mut c_void, *mut ACameraCaptureSession),
        pub on_active: extern "C" fn(*mut c_void, *mut ACameraCaptureSession),
    }

    extern "C" {
        pub fn ACameraManager_create() -> *mut ACameraManager;
        pub fn ACameraManager_delete(mgr: *mut ACameraManager);
        pub fn ACameraManager_getCameraIdList(
            mgr: *mut ACameraManager,
            list: *mut *mut ACameraIdList,
        ) -> c_int;
        pub fn ACameraManager_deleteCameraIdList(list: *mut ACameraIdList);
        pub fn ACameraManager_openCamera(
            mgr: *mut ACameraManager,
            camera_id: *const c_char,
            cbs: *mut ACameraDevice_StateCallbacks,
            device: *mut *mut ACameraDevice,
        ) -> c_int;

        pub fn ACameraDevice_close(device: *mut ACameraDevice) -> c_int;
        pub fn ACameraDevice_createCaptureRequest(
            device: *mut ACameraDevice,
            template: c_int,
            request: *mut *mut ACaptureRequest,
        ) -> c_int;
        pub fn ACameraDevice_createCaptureSession(
            device: *mut ACameraDevice,
            outputs: *const ACaptureSessionOutputContainer,
            cbs: *const ACameraCaptureSession_stateCallbacks,
            session: *mut *mut ACameraCaptureSession,
        ) -> c_int;

        pub fn ACaptureRequest_addTarget(
            req: *mut ACaptureRequest,
            target: *const ACameraOutputTarget,
        ) -> c_int;

        pub fn ACameraOutputTarget_create(
            window: *mut ANativeWindow,
            out: *mut *mut ACameraOutputTarget,
        ) -> c_int;
        pub fn ACaptureSessionOutput_create(
            window: *mut ANativeWindow,
            out: *mut *mut ACaptureSessionOutput,
        ) -> c_int;
        pub fn ACaptureSessionOutputContainer_create(
            out: *mut *mut ACaptureSessionOutputContainer,
        ) -> c_int;
        pub fn ACaptureSessionOutputContainer_add(
            container: *mut ACaptureSessionOutputContainer,
            output: *const ACaptureSessionOutput,
        ) -> c_int;

        pub fn ACameraCaptureSession_setRepeatingRequest(
            session: *mut ACameraCaptureSession,
            cbs: *mut c_void,
            num_requests: c_int,
            requests: *mut *mut ACaptureRequest,
            capture_sequence_id: *mut c_int,
        ) -> c_int;
        pub fn ACameraCaptureSession_close(session: *mut ACameraCaptureSession);

        pub fn AImageReader_new(
            width: c_int,
            height: c_int,
            format: c_int,
            max_images: c_int,
            reader: *mut *mut AImageReader,
        ) -> c_int;
        pub fn AImageReader_delete(reader: *mut AImageReader);
        pub fn AImageReader_getWindow(
            reader: *mut AImageReader,
            window: *mut *mut ANativeWindow,
        ) -> c_int;
        pub fn AImageReader_acquireLatestImage(
            reader: *mut AImageReader,
            image: *mut *mut AImage,
        ) -> c_int;

        pub fn AImage_delete(image: *mut AImage);
        pub fn AImage_getWidth(image: *const AImage, width: *mut i32) -> c_int;
        pub fn AImage_getHeight(image: *const AImage, height: *mut i32) -> c_int;
        pub fn AImage_getPlaneRowStride(
            image: *const AImage,
            plane_idx: c_int,
            row_stride: *mut i32,
        ) -> c_int;
        pub fn AImage_getPlaneData(
            image: *const AImage,
            plane_idx: c_int,
            data: *mut *mut u8,
            data_length: *mut c_int,
        ) -> c_int;
    }
}

use ffi::*;

const AIMAGE_FORMAT_YUV_420_888: c_int = 0x23;
const TEMPLATE_PREVIEW: c_int = 1;

extern "C" fn on_disconnected(_c: *mut c_void, _d: *mut ACameraDevice) {}
extern "C" fn on_error(_c: *mut c_void, _d: *mut ACameraDevice, _e: c_int) {}
extern "C" fn on_session(_c: *mut c_void, _s: *mut ACameraCaptureSession) {}

/// Downscale a strided grayscale plane to RGBA (gray → R=G=B), longest side
/// ≤ `maxdim` — small enough to push through the UI event loop per frame.
fn luma_to_rgba_scaled(
    luma: &[u8],
    w: usize,
    h: usize,
    stride: usize,
    maxdim: usize,
) -> (Vec<u8>, u32, u32) {
    let scale = ((w.max(h) as f32) / maxdim as f32).max(1.0);
    let ow = (((w as f32) / scale) as usize).max(1);
    let oh = (((h as f32) / scale) as usize).max(1);
    let mut out = vec![0u8; ow * oh * 4];
    for y in 0..oh {
        let row = ((y as f32) * scale) as usize * stride;
        for x in 0..ow {
            let g = luma[row + ((x as f32) * scale) as usize];
            let o = (y * ow + x) * 4;
            out[o] = g;
            out[o + 1] = g;
            out[o + 2] = g;
            out[o + 3] = 255;
        }
    }
    (out, ow as u32, oh as u32)
}

/// Capture frames for up to `seconds` (or until `cancel`), pushing each as a
/// downscaled RGBA preview and feeding each decoded QR payload to `feed`.
/// Stops (returns `true`) when `feed` returns `true`.
pub fn capture_frames(
    seconds: u64,
    cancel: &AtomicBool,
    mut preview: impl FnMut(&[u8], u32, u32),
    mut feed: impl FnMut(&[u8]) -> bool,
) -> Result<bool, String> {
    unsafe {
        let mgr = ACameraManager_create();
        if mgr.is_null() {
            return Err("ACameraManager_create null".into());
        }
        let mut id_list: *mut ACameraIdList = ptr::null_mut();
        if ACameraManager_getCameraIdList(mgr, &mut id_list) != 0 || id_list.is_null() {
            ACameraManager_delete(mgr);
            return Err("getCameraIdList failed".into());
        }
        let n = (*id_list).num_cameras;
        if n < 1 {
            ACameraManager_deleteCameraIdList(id_list);
            ACameraManager_delete(mgr);
            return Err(format!("no cameras (num={n})"));
        }
        let cam_id = *(*id_list).camera_ids.offset(0);

        let (w, h) = (640, 480);
        let mut reader: *mut AImageReader = ptr::null_mut();
        if AImageReader_new(w, h, AIMAGE_FORMAT_YUV_420_888, 4, &mut reader) != 0
            || reader.is_null()
        {
            ACameraManager_deleteCameraIdList(id_list);
            ACameraManager_delete(mgr);
            return Err("AImageReader_new failed".into());
        }
        let mut window: *mut ANativeWindow = ptr::null_mut();
        if AImageReader_getWindow(reader, &mut window) != 0 || window.is_null() {
            AImageReader_delete(reader);
            ACameraManager_deleteCameraIdList(id_list);
            ACameraManager_delete(mgr);
            return Err("AImageReader_getWindow failed".into());
        }

        let mut dev_cbs = ACameraDevice_StateCallbacks {
            context: ptr::null_mut(),
            on_disconnected,
            on_error,
        };
        let mut device: *mut ACameraDevice = ptr::null_mut();
        let st = ACameraManager_openCamera(mgr, cam_id, &mut dev_cbs, &mut device);
        if st != 0 || device.is_null() {
            AImageReader_delete(reader);
            ACameraManager_deleteCameraIdList(id_list);
            ACameraManager_delete(mgr);
            return Err(format!("openCamera status={st}"));
        }
        eprintln!("cb: cam opened {w}x{h} (android ndk)");

        let mut request: *mut ACaptureRequest = ptr::null_mut();
        ACameraDevice_createCaptureRequest(device, TEMPLATE_PREVIEW, &mut request);
        let mut target: *mut ACameraOutputTarget = ptr::null_mut();
        ACameraOutputTarget_create(window, &mut target);
        ACaptureRequest_addTarget(request, target);

        let mut sess_out: *mut ACaptureSessionOutput = ptr::null_mut();
        ACaptureSessionOutput_create(window, &mut sess_out);
        let mut container: *mut ACaptureSessionOutputContainer = ptr::null_mut();
        ACaptureSessionOutputContainer_create(&mut container);
        ACaptureSessionOutputContainer_add(container, sess_out);

        let sess_cbs = ACameraCaptureSession_stateCallbacks {
            context: ptr::null_mut(),
            on_closed: on_session,
            on_ready: on_session,
            on_active: on_session,
        };
        let mut session: *mut ACameraCaptureSession = ptr::null_mut();
        let st = ACameraDevice_createCaptureSession(device, container, &sess_cbs, &mut session);
        if st != 0 || session.is_null() {
            ACameraDevice_close(device);
            AImageReader_delete(reader);
            ACameraManager_deleteCameraIdList(id_list);
            ACameraManager_delete(mgr);
            return Err(format!("createCaptureSession status={st}"));
        }
        ACameraCaptureSession_setRepeatingRequest(session, ptr::null_mut(), 1, &mut request, ptr::null_mut());

        let start = std::time::Instant::now();
        let mut done = false;
        let mut frames = 0u64;
        while start.elapsed().as_secs() < seconds && !cancel.load(Ordering::Relaxed) {
            let mut image: *mut AImage = ptr::null_mut();
            let st = AImageReader_acquireLatestImage(reader, &mut image);
            if st != 0 || image.is_null() {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            let mut iw = 0i32;
            let mut ih = 0i32;
            AImage_getWidth(image, &mut iw);
            AImage_getHeight(image, &mut ih);
            let mut stride = 0i32;
            AImage_getPlaneRowStride(image, 0, &mut stride);
            let mut data: *mut u8 = ptr::null_mut();
            let mut len: c_int = 0;
            AImage_getPlaneData(image, 0, &mut data, &mut len);

            if !data.is_null() && iw > 0 && ih > 0 && stride >= iw {
                let luma = std::slice::from_raw_parts(data, len as usize);
                let (ww, hh, ss) = (iw as usize, ih as usize, stride as usize);
                frames += 1;

                let (rgba, pw, ph) = luma_to_rgba_scaled(luma, ww, hh, ss, 420);
                preview(&rgba, pw, ph);

                // QR detect every other frame — keeps the preview smooth.
                if frames % 2 == 0 {
                    let mut prepared =
                        rqrr::PreparedImage::prepare_from_greyscale(ww, hh, |x, y| luma[y * ss + x]);
                    for grid in prepared.detect_grids() {
                        let mut payload = Vec::new();
                        if grid.decode_to(&mut payload).is_ok() && feed(&payload) {
                            done = true;
                            break;
                        }
                    }
                }
            }
            AImage_delete(image);
            if done {
                break;
            }
        }

        // Teardown so the camera can be reopened on the next scan.
        ACameraCaptureSession_close(session);
        ACameraDevice_close(device);
        AImageReader_delete(reader);
        ACameraManager_deleteCameraIdList(id_list);
        ACameraManager_delete(mgr);
        Ok(done)
    }
}

/// Single-shot: capture (with preview) until one QR decodes, or cancel/timeout.
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
