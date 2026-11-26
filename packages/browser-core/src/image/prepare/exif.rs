//! EXIF orientation from the bounded JPEG APP1 or WebP EXIF segment.

pub fn read(data: &[u8], mime: &str) -> Option<u16> {
    let tiff = match mime {
        "image/jpeg" => jpeg(data)?,
        "image/webp" => webp(data)?,
        _ => return None,
    };
    let little = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let read16 = |at: usize| {
        let raw: [u8; 2] = tiff.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    };
    let read32 = |at: usize| {
        let raw: [u8; 4] = tiff.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    if read16(2)? != 42 {
        return None;
    }
    let offset = read32(4)? as usize;
    let n = usize::from(read16(offset)?);
    for i in 0..n {
        let at = offset.checked_add(2)?.checked_add(i * 12)?;
        if read16(at)? == 0x0112
            && read16(at.checked_add(2)?)? == 3
            && read32(at.checked_add(4)?)? == 1
        {
            let n = read16(at.checked_add(8)?)?;
            return (1..=8).contains(&n).then_some(n);
        }
    }
    None
}

fn jpeg(data: &[u8]) -> Option<&[u8]> {
    let mut at = 2;
    while data.get(at) == Some(&0xff) {
        let marker = *data.get(at + 1)?;
        at += 2;
        if marker == 0xff {
            at -= 1;
            continue;
        }
        if matches!(marker, 0xda | 0xd9) {
            return None;
        }
        if matches!(marker, 0x01 | 0xd0..=0xd8) {
            continue;
        }
        let bytes = usize::from(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?));
        let end = at.checked_add(bytes)?;
        let payload = data.get(at + 2..end)?;
        if marker == 0xe1 {
            if let Some(tiff) = payload.strip_prefix(b"Exif\0\0") {
                return Some(tiff);
            }
        }
        at = end;
    }
    None
}

fn webp(data: &[u8]) -> Option<&[u8]> {
    let mut at = 12usize;
    while let Some(header) = data.get(at..at + 8) {
        let bytes = u32::from_le_bytes(header[4..].try_into().ok()?) as usize;
        let end = at.checked_add(8)?.checked_add(bytes)?;
        let payload = data.get(at + 8..end)?;
        if header.starts_with(b"EXIF") {
            return Some(payload.strip_prefix(b"Exif\0\0").unwrap_or(payload));
        }
        at = end.checked_add(bytes % 2)?;
    }
    None
}
