//! QR pipeline round-trip with no optics: qrcode-render → grayscale
//! pixels → rqrr decode. Proves the decode leg the camera spike can't
//! prove deterministically (the optical leg is M7's webcam recipe).

fn render_gray(data: &str, scale: usize) -> (Vec<u8>, usize) {
    let code = qrcode::QrCode::new(data.as_bytes()).unwrap();
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 2 * scale; // mirrors src/qr.rs (2 embedded modules; the UI card pads the rest)
    let side = width * scale + quiet * 2;
    let mut img = vec![255u8; side * side];
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        img[(quiet + y * scale + dy) * side + quiet + x * scale + dx] = 0;
                    }
                }
            }
        }
    }
    (img, side)
}

fn decode(img: &[u8], side: usize) -> Option<Vec<u8>> {
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| img[y * side + x]);
    for grid in prepared.detect_grids() {
        let mut payload = Vec::new();
        if grid.decode_to(&mut payload).is_ok() {
            return Some(payload);
        }
    }
    None
}

#[test]
fn address_qr_roundtrip() {
    let addr = "TB1P548GT356P9JRHR6P5HFVD83KM5ZUS936HLCFYZL0XHMTG5AV2ARQUY4WPK";
    let (img, side) = render_gray(addr, 4);
    assert_eq!(decode(&img, side).as_deref(), Some(addr.as_bytes()));
}

#[test]
fn seedqr_digits_roundtrip() {
    // 12-word standard SeedQR digit stream (48 digits).
    let digits = "071507501750091509131802186716340031120517640134";
    let (img, side) = render_gray(digits, 4);
    assert_eq!(decode(&img, side).as_deref(), Some(digits.as_bytes()));
}
