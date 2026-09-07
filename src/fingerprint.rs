//! Receiver fingerprint: everything a dongle keyslot can bind to.
//!
//! TI Unifying (CU-0008) primary, Nano (CU-0010) as second possession
//! factor. Material (`uniseal-fp-v1`) for a given `(dongles, bind)`
//! selection, every variable field length-prefixed:
//! ```text
//! "uniseal-fp-v1" dongles(1) bind(1)
//! [TI]   pid(2) serial(4) { slot(1) wpid(2) len(1) serial len(1) record }  for each slot in bind
//! [Nano] pid(2) serial(4)
//! ```
//! `record` is the 16-byte pairing record read through the D4 register on
//! firmwares that still expose it: receiver serial, device WPID, receiver
//! WPID (8808) and the two 4-byte pairing nonces. That is the input of the
//! AES link key derivation, not the key itself: 64 fresh bits per device.
//! `bind` selects which receiver slots take part (0 = receiver alone), so
//! a vault can survive pairing new devices. Firmware version deliberately
//! EXCLUDED, and so is the Nano "rfs" scratch byte (register 0x03): it was
//! measured to reset to 0x00 on every power cycle, so binding to it would
//! brick vaults at the next unplug.
//!
//! Robustness rules: a timeout on any register aborts the read (never
//! substitute zeros or skip a receiver), and `collect` requires two
//! consecutive identical reads before handing the fingerprint out.

use crate::hid::{self, HidApi, Reply};
use crate::vault::{self, DONGLE_NANO, DONGLE_TI, Dongle, DongleSource, Secret};
use hidapi::HidDevice;
use std::fmt;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FpError {
    NoReceiver,
    Unresponsive(String),
    Unstable,
}

impl fmt::Display for FpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FpError::NoReceiver => write!(f, "no supported receiver (CU-0008 / CU-0010)"),
            FpError::Unresponsive(w) => write!(f, "receiver did not answer ({w}); close Solaar / Logi Options and retry"),
            FpError::Unstable => write!(f, "fingerprint differed between consecutive reads; refusing to use it"),
        }
    }
}

impl std::error::Error for FpError {}

#[derive(Clone, Debug)]
pub struct SlotInfo {
    pub slot: u8,
    pub wpid: [u8; 2],
    pub kind: String,
    pub name: String,
    pub serial: Vec<u8>,
    pub record: Option<Zeroizing<[u8; 16]>>,
}

impl SlotInfo {
    pub fn wpid_hex(&self) -> String {
        vault::hex(&self.wpid)
    }
}

#[derive(Clone, Default, Debug)]
pub struct Fingerprint {
    pub ti_present: bool,
    pub receiver_serial: Vec<u8>,
    pub firmware: String,
    pub d4_open: bool,
    pub slots: Vec<SlotInfo>,
    pub nano_present: bool,
    pub nano_serial: Vec<u8>,
}

impl Fingerprint {
    /// Receiver slots occupied right now, as a bind mask.
    pub fn occupied(&self) -> u8 {
        self.slots.iter().fold(0, |m, s| m | (1 << (s.slot - 1)))
    }

    pub fn nkeys(&self) -> u8 {
        self.slots.iter().filter(|s| s.record.is_some()).count() as u8
    }

    fn nkeys_in(&self, bind: u8) -> u8 {
        self.slots.iter().filter(|s| bind & (1 << (s.slot - 1)) != 0 && s.record.is_some()).count() as u8
    }

    /// Material + description for the plugged receivers, bound to `bind`
    /// (`None` = every occupied slot).
    pub fn dongle(&self, bind: Option<u8>) -> Result<Dongle, String> {
        let bind = bind.unwrap_or_else(|| self.occupied());
        let dongles = self.plugged();
        let material = self.material(dongles, bind)?;
        Ok(Dongle { material, dongles, nkeys: self.nkeys_in(bind), bind })
    }

    /// Public tag of the full fingerprint (everything plugged, every slot).
    pub fn kid(&self) -> [u8; 8] {
        self.material(self.plugged(), self.occupied()).map(|m| vault::kid(&m)).unwrap_or([0; 8])
    }

    pub fn grade(&self) -> String {
        let keys = self.nkeys();
        if keys > 0 { format!("pairing records ({keys})") } else { "serials only".to_string() }
    }

    pub fn summary(&self) -> String {
        let mut dongles = Vec::new();
        if self.ti_present {
            dongles.push(format!("TI C52B {}", self.firmware));
        }
        if self.nano_present {
            dongles.push("Nano C52F".to_string());
        }
        format!("{} | slots {} | grade: {}", dongles.join(" + "), self.slots.len(), self.grade())
    }
}

impl DongleSource for Fingerprint {
    fn plugged(&self) -> u8 {
        (if self.ti_present { DONGLE_TI } else { 0 }) | (if self.nano_present { DONGLE_NANO } else { 0 })
    }

    fn material(&self, dongles: u8, bind: u8) -> Result<Secret, String> {
        if dongles == 0 {
            return Err("no receiver selected".into());
        }
        if dongles & !self.plugged() != 0 {
            return Err(format!(
                "needs dongle {}, plugged {}",
                vault::dongles_label(dongles),
                vault::dongles_label(self.plugged())
            ));
        }
        let mut m: Secret = Zeroizing::new(Vec::new());
        m.extend_from_slice(b"uniseal-fp-v1");
        m.push(dongles);
        m.push(bind);
        if dongles & DONGLE_TI != 0 {
            m.extend_from_slice(&hid::TI_PID.to_be_bytes());
            m.extend_from_slice(&self.receiver_serial);
            for slot in 1u8..=6 {
                if bind & (1 << (slot - 1)) == 0 {
                    continue;
                }
                let s = self
                    .slots
                    .iter()
                    .find(|s| s.slot == slot)
                    .ok_or_else(|| format!("device in receiver slot {slot} missing (unpaired or re-paired?)"))?;
                m.push(slot);
                m.extend_from_slice(&s.wpid);
                push_field(&mut m, &s.serial);
                match &s.record {
                    Some(r) => push_field(&mut m, &r[..]),
                    None => push_field(&mut m, &[]),
                }
            }
        }
        if dongles & DONGLE_NANO != 0 {
            m.extend_from_slice(&hid::NANO_PID.to_be_bytes());
            m.extend_from_slice(&self.nano_serial);
        }
        Ok(m)
    }
}

fn bcd_byte(b: u8) -> String {
    format!("{}{}", b >> 4, b & 0x0F)
}

/// `Silent` aborts the read; `Refused` is a legitimate "no data".
fn need<T>(r: Reply<T>, what: &str) -> Result<Option<T>, FpError> {
    match r {
        Reply::Data(d) => Ok(Some(d)),
        Reply::Refused => Ok(None),
        Reply::Silent => Err(FpError::Unresponsive(what.to_string())),
    }
}

fn push_field(m: &mut Vec<u8>, bytes: &[u8]) {
    m.push(bytes.len() as u8);
    m.extend_from_slice(bytes);
}

fn read_ti(dev: &HidDevice, fp: &mut Fingerprint) -> Result<(), FpError> {
    let serial = need(hid::long_get(dev, 0xB5, 0x03), "TI B5/03")?
        .ok_or_else(|| FpError::Unresponsive("TI B5/03 refused".into()))?;
    fp.ti_present = true;
    fp.receiver_serial = serial[..4].to_vec();

    // Firmware: display only, never part of the material.
    let (mut major, mut minor, mut build) = ("??".to_string(), "??".to_string(), "????".to_string());
    if let Some(v1) = hid::short_get(dev, 0xF1, 0x01).data() {
        major = bcd_byte(v1[1]);
        minor = bcd_byte(v1[2]);
        if let Some(v2) = hid::short_get(dev, 0xF1, 0x02).data() {
            build = format!("{:02X}{:02X}", v2[1], v2[2]);
        }
    }
    fp.firmware = format!("RQR{major}.{minor}_B{build}");

    let mut active = 0u16;
    for page in [0xE400u16, 0xE800, 0xEC00, 0xF000] {
        if hid::d4read(dev, page) == Reply::Data(0x3F) {
            active = page;
            break;
        }
    }
    fp.d4_open = active != 0;

    for slot in 1u8..=6 {
        let Some(p) = need(hid::long_get(dev, 0xB5, 0x20 + slot - 1), "TI B5/2x")? else { continue };
        let kind = match p[6] {
            1 => "keyboard".to_string(),
            2 => "mouse".to_string(),
            k => format!("kind{k:02X}"),
        };
        let name = hid::long_get(dev, 0xB5, 0x40 + slot - 1)
            .data()
            .map(|n| {
                let l = n[0].min(14) as usize;
                String::from_utf8_lossy(&n[1..1 + l]).into_owned()
            })
            .unwrap_or_default();
        let serial = need(hid::long_get(dev, 0xB5, 0x30 + slot - 1), "TI B5/3x")?
            .map(|e| e[..4].to_vec())
            .unwrap_or_default();
        let mut record: Option<Zeroizing<[u8; 16]>> = None;
        if active != 0 {
            let marker = 0x60 + (slot - 1);
            for step in 0..33u16 {
                let base = active + 4 + 0x14 * step;
                match hid::d4read(dev, base) {
                    Reply::Data(b) if b == marker => {
                        let mut r = Zeroizing::new([0u8; 16]);
                        for i in 0..16u16 {
                            r[i as usize] = need(hid::d4read(dev, base + 4 + i), "TI D4 record")?
                                .ok_or_else(|| FpError::Unresponsive("TI D4 record refused".into()))?;
                        }
                        record = Some(r);
                        break;
                    }
                    Reply::Data(_) | Reply::Refused => {}
                    Reply::Silent => return Err(FpError::Unresponsive("TI D4 scan".into())),
                }
            }
        }
        fp.slots.push(SlotInfo { slot, wpid: [p[2], p[3]], kind, name, serial, record });
    }
    Ok(())
}

fn read_nano(dev: &HidDevice, fp: &mut Fingerprint) -> Result<(), FpError> {
    let serial = need(hid::long_get(dev, 0xB5, 0x03), "Nano B5/03")?
        .ok_or_else(|| FpError::Unresponsive("Nano B5/03 refused".into()))?;
    fp.nano_present = true;
    fp.nano_serial = serial[..4].to_vec();
    Ok(())
}

fn read_once(api: &HidApi) -> Result<Fingerprint, FpError> {
    let mut fp = Fingerprint::default();
    if let Some(dev) = hid::open_vendor(api, hid::TI_PID) {
        read_ti(&dev, &mut fp)?;
    }
    if let Some(dev) = hid::open_vendor(api, hid::NANO_PID) {
        read_nano(&dev, &mut fp)?;
    }
    if !fp.ti_present && !fp.nano_present {
        return Err(FpError::NoReceiver);
    }
    Ok(fp)
}

/// Read the fingerprint from any combination (TI only, Nano only, both).
/// Two consecutive reads must agree on the full material, else `Unstable`.
pub fn collect(api: &HidApi) -> Result<Fingerprint, FpError> {
    let mut last: Option<Fingerprint> = None;
    for _ in 0..3 {
        let fp = read_once(api)?;
        if let Some(prev) = &last
            && prev.material(prev.plugged(), prev.occupied()).ok() == fp.material(fp.plugged(), fp.occupied()).ok()
        {
            return Ok(fp);
        }
        last = Some(fp);
    }
    Err(FpError::Unstable)
}

/// Parse `--bind`: `all`, `receiver`, or a list of receiver slots `1,3`.
pub fn parse_bind(s: &str) -> Result<Option<u8>, String> {
    match s.trim() {
        "all" | "" => Ok(None),
        "receiver" | "none" => Ok(Some(0)),
        list => {
            let mut mask = 0u8;
            for part in list.split(',') {
                let n: u8 = part.trim().parse().map_err(|_| format!("bad slot '{part}' (expected 1-6)"))?;
                if !(1..=6).contains(&n) {
                    return Err(format!("slot {n} out of range 1-6"));
                }
                mask |= 1 << (n - 1);
            }
            Ok(Some(mask))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> Fingerprint {
        Fingerprint {
            ti_present: true,
            receiver_serial: vec![0x11, 0x22, 0x33, 0x44],
            firmware: "RQR00.00_B0000".into(),
            d4_open: true,
            slots: vec![
                SlotInfo { slot: 1, wpid: [0x40, 0x4D], kind: "keyboard".into(), name: "K1".into(), serial: vec![1, 2, 3, 4], record: Some(Zeroizing::new([7; 16])) },
                SlotInfo { slot: 3, wpid: [0x40, 0x8A], kind: "mouse".into(), name: "M3".into(), serial: vec![5, 6, 7, 8], record: None },
            ],
            nano_present: false,
            nano_serial: vec![],
        }
    }

    #[test]
    fn binding_and_material() {
        let f = fp();
        assert_eq!(f.occupied(), 0b101);
        assert_eq!(parse_bind("all").unwrap(), None);
        assert_eq!(parse_bind("receiver").unwrap(), Some(0));
        assert_eq!(parse_bind("1,3").unwrap(), Some(0b101));
        assert!(parse_bind("7").is_err());
        let all = f.dongle(None).unwrap();
        assert_eq!((all.bind, all.nkeys, all.dongles), (0b101, 1, DONGLE_TI));
        let recv = f.dongle(Some(0)).unwrap();
        assert_eq!((recv.bind, recv.nkeys), (0, 0));
        assert_ne!(all.material, recv.material);
        assert!(f.dongle(Some(0b010)).unwrap_err().contains("slot 2 missing"));
        assert!(f.material(DONGLE_NANO, 0).unwrap_err().contains("needs dongle Nano"));
        // Pairing a new device in slot 2 leaves a slots-1,3 material untouched.
        let mut more = f.clone();
        more.slots.push(SlotInfo { slot: 2, wpid: [0, 1], kind: "mouse".into(), name: "new".into(), serial: vec![9], record: None });
        assert_eq!(more.material(DONGLE_TI, 0b101).unwrap(), f.material(DONGLE_TI, 0b101).unwrap());
        assert_ne!(more.dongle(None).unwrap().material, all.material);
    }
}
