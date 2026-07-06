//! QR out: string → slint Image (address QR now; SeedQR reveal at M6).

pub fn qr_image(data: &str) -> Option<slint::Image> {
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let quiet = 4usize;
    let side = width + quiet * 2;
    let mut buf = slint::SharedPixelBuffer::<slint::Rgb8Pixel>::new(side as u32, side as u32);
    let px = buf.make_mut_slice();
    for p in px.iter_mut() {
        *p = slint::Rgb8Pixel { r: 255, g: 255, b: 255 };
    }
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                px[(y + quiet) * side + (x + quiet)] = slint::Rgb8Pixel { r: 0, g: 0, b: 0 };
            }
        }
    }
    Some(slint::Image::from_rgb8(buf))
}
