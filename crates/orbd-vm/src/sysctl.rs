//! macOS `sysctlbyname` reads.

use nix::libc;

/// A sysctl's raw value.
pub fn bytes(name: &str) -> Option<Vec<u8>> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    // SAFETY: size query with a null buffer.
    let r = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` holds `len` bytes.
    let r = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    buf.truncate(len);
    Some(buf)
}

/// A string sysctl, trimmed; empty if unreadable.
pub fn string(name: &str) -> String {
    bytes(name)
        .map(|b| {
            String::from_utf8_lossy(b.split(|c| *c == 0).next().unwrap_or_default())
                .trim()
                .to_owned()
        })
        .unwrap_or_default()
}

/// An integer sysctl (4 or 8 bytes).
pub fn u64(name: &str) -> Option<u64> {
    let b = bytes(name)?;
    match b.len() {
        4 => Some(u32::from_ne_bytes(b.try_into().ok()?).into()),
        8 => Some(u64::from_ne_bytes(b.try_into().ok()?)),
        _ => None,
    }
}
