//! USB/HID primitives for Logitech receivers (hidapi).
//!
//! Two report styles exist on these firmwares:
//! - short reports (`0x10`, 7 bytes) for HID++ 1.0 GET/SET;
//! - long GETs sent as SHORT reports with sub `0x83`, answered LONG (`0x11`).
//!   Long `0x11` requests are rejected, so `long_get` uses the short form.
//!
//! Every GET distinguishes three outcomes, because the fingerprint must
//! never silently absorb a timeout as "no data":
//! - `Data`: the register answered;
//! - `Refused`: HID++ error frame `8F` (unoccupied slot, closed register);
//! - `Silent`: no matching frame in time (bus glitch, contention with
//!   Solaar / Logi Options). Callers retry or abort, they never guess.

use hidapi::HidDevice;

pub use hidapi::HidApi;

pub const LOGITECH_VID: u16 = 0x046D;
pub const TI_PID: u16 = 0xC52B;
pub const NANO_PID: u16 = 0xC52F;
const VENDOR_PAGE: u16 = 0xFF00;
const ERR_SUBID: u8 = 0x8F;
const TIMEOUT_MS: i32 = 150;
const MAX_FRAMES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply<T> {
    Data(T),
    Refused,
    Silent,
}

impl<T> Reply<T> {
    pub fn data(self) -> Option<T> {
        match self {
            Reply::Data(d) => Some(d),
            _ => None,
        }
    }
}

/// Open the HID++ vendor collection (usage page 0xFF00) of a receiver.
pub fn open_vendor(api: &HidApi, pid: u16) -> Option<HidDevice> {
    for d in api.device_list() {
        if d.vendor_id() == LOGITECH_VID && d.product_id() == pid && d.usage_page() == VENDOR_PAGE
            && let Ok(dev) = api.open_path(d.path())
        {
            let _ = dev.set_blocking_mode(false);
            return Some(dev);
        }
    }
    None
}

fn recv(dev: &HidDevice) -> Option<[u8; 64]> {
    let mut buf = [0u8; 64];
    match dev.read_timeout(&mut buf, TIMEOUT_MS) {
        Ok(n) if n > 0 => Some(buf),
        _ => None,
    }
}

/// Wait for the answer to `(sub, reg)`: a matching data frame (filtered by
/// `accept`) or the matching HID++ error frame. Unrelated frames
/// (notifications, stale answers) are skipped.
fn answer(dev: &HidDevice, sub: u8, reg: u8, accept: impl Fn(&[u8; 64]) -> bool) -> Reply<[u8; 64]> {
    for _ in 0..MAX_FRAMES {
        let Some(buf) = recv(dev) else { return Reply::Silent };
        if buf[1] != 0xFF {
            continue;
        }
        if buf[2] == ERR_SUBID && buf[3] == sub && buf[4] == reg {
            return Reply::Refused;
        }
        if buf[2] == sub && buf[3] == reg && accept(&buf) {
            return Reply::Data(buf);
        }
    }
    Reply::Silent
}

fn send(dev: &HidDevice, req: &[u8; 7]) -> bool {
    dev.write(req).is_ok()
}

/// Short HID++ 1.0 GET: `[10 FF 81 reg p0 00 00]`. Returns 3 data bytes.
pub fn short_get(dev: &HidDevice, reg: u8, p0: u8) -> Reply<[u8; 3]> {
    if !send(dev, &[0x10, 0xFF, 0x81, reg, p0, 0x00, 0x00]) {
        return Reply::Silent;
    }
    match answer(dev, 0x81, reg, |_| true) {
        Reply::Data(b) => Reply::Data([b[4], b[5], b[6]]),
        Reply::Refused => Reply::Refused,
        Reply::Silent => Reply::Silent,
    }
}

/// Long GET via short report: `[10 FF 83 reg sub 00 00]`, 15-byte answer.
pub fn long_get(dev: &HidDevice, reg: u8, sub: u8) -> Reply<[u8; 15]> {
    if !send(dev, &[0x10, 0xFF, 0x83, reg, sub, 0x00, 0x00]) {
        return Reply::Silent;
    }
    match answer(dev, 0x83, reg, |b| b[0] == 0x11 && b[4] == sub) {
        Reply::Data(b) => {
            let mut out = [0u8; 15];
            out.copy_from_slice(&b[5..20]);
            Reply::Data(out)
        }
        Reply::Refused => Reply::Refused,
        Reply::Silent => Reply::Silent,
    }
}

/// `GET [D4 LSB MSB]` answers one flash byte.
pub fn d4read(dev: &HidDevice, addr: u16) -> Reply<u8> {
    if !send(dev, &[0x10, 0xFF, 0x81, 0xD4, (addr & 0xFF) as u8, (addr >> 8) as u8, 0x00]) {
        return Reply::Silent;
    }
    match answer(dev, 0x81, 0xD4, |_| true) {
        Reply::Data(b) => Reply::Data(b[6]),
        Reply::Refused => Reply::Refused,
        Reply::Silent => Reply::Silent,
    }
}
