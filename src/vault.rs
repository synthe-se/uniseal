//! Vault format v1: LUKS-style keyslots around a random 256-bit file key,
//! body encrypted in chunks so files of any size stream through.
//!
//! ```text
//! MAGIC(8) | nslots(1) | slot x nslots | body
//! slot = kind(1) dongles(1) nkeys(1) bind(1) kid(8) salt(16) m_kib(4) t(4) p(4)   40 B, AAD of the wrap
//!        nonce(24) wrapped(32 + 16 tag)                                           72 B
//! body = prefix(19) | chunk*      chunk = XChaCha20-Poly1305(file key, <= 1 MiB, aad = MAGIC)
//!        nonce of chunk i = prefix || i (u32 BE) || last (0 or 1)
//! ```
//!
//! The file key is random, so re-keying never touches the body. Each slot
//! wraps it under a KEK = HKDF-SHA256(salt, ikm) with
//! ikm = [Argon2id(pass, salt) 32 B] ++ [fingerprint material], layout
//! fixed by `kind`. `bind` records which receiver slots the material was
//! built from, so pairing a new device later does not change the key.
//! `kid` = HKDF(material) under a separate salt and info: a public one-way
//! tag naming the dongle set a slot needs. The chunk counter and last flag
//! in the nonce make reordering and truncation detectable (STREAM).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fmt;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"UNISEAL1";
pub const MAX_SLOTS: usize = 8;
pub const CHUNK: usize = 1 << 20;
const SLOT_AAD: usize = 40;
const SLOT_LEN: usize = SLOT_AAD + 24 + 48;
const PREFIX: usize = 19;
const TAG: usize = 16;
pub const DONGLE_TI: u8 = 1;
pub const DONGLE_NANO: u8 = 2;

pub type Key = Zeroizing<[u8; 32]>;
pub type Secret = Zeroizing<Vec<u8>>;
pub type Rng<'a> = dyn FnMut(&mut [u8]) -> Result<(), Error> + 'a;

pub fn os_rng(buf: &mut [u8]) -> Result<(), Error> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NotVault,
    Truncated,
    Corrupt(String),
    Io(String),
    Rng,
    TooManySlots,
    LastSlot,
    NoSuchSlot,
    BadSpec(&'static str),
    Argon,
    WrongKey,
    NoUsableSlot(Vec<String>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotVault => write!(f, "not a uniseal vault (magic missing)"),
            Error::Truncated => write!(f, "vault truncated"),
            Error::Corrupt(w) => write!(f, "vault corrupt: {w}"),
            Error::Io(w) => write!(f, "i/o: {w}"),
            Error::Rng => write!(f, "system RNG unavailable"),
            Error::TooManySlots => write!(f, "vault already has {MAX_SLOTS} keyslots"),
            Error::LastSlot => write!(f, "refusing to remove the last keyslot"),
            Error::NoSuchSlot => write!(f, "no such keyslot"),
            Error::BadSpec(w) => write!(f, "{w}"),
            Error::Argon => write!(f, "Argon2 parameters rejected"),
            Error::WrongKey => write!(f, "wrong key: refused"),
            Error::NoUsableSlot(reasons) => {
                write!(f, "no keyslot opened:")?;
                for r in reasons {
                    write!(f, "\n  {r}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// Possession only: whoever holds the dongles opens it.
    Dongle = 1,
    /// Passphrase only: recovery slot, works without any dongle.
    Pass = 2,
    /// Dongles AND a PIN: the real second factor.
    DonglePass = 3,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Dongle),
            2 => Some(Kind::Pass),
            3 => Some(Kind::DonglePass),
            _ => None,
        }
    }
    pub fn needs_dongle(self) -> bool {
        matches!(self, Kind::Dongle | Kind::DonglePass)
    }
    pub fn needs_pass(self) -> bool {
        matches!(self, Kind::Pass | Kind::DonglePass)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Argon {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

pub const ARGON_DEFAULT: Argon = Argon { m_kib: 64 * 1024, t: 3, p: 1 };
const ARGON_NONE: Argon = Argon { m_kib: 0, t: 0, p: 0 };

pub fn dongles_label(mask: u8) -> String {
    let mut v = Vec::new();
    if mask & DONGLE_TI != 0 {
        v.push("TI");
    }
    if mask & DONGLE_NANO != 0 {
        v.push("Nano");
    }
    if v.is_empty() { "none".to_string() } else { v.join("+") }
}

/// Human list of the receiver slots in a bind mask.
pub fn bind_label(bind: u8) -> String {
    let slots: Vec<String> = (0..6).filter(|i| bind & (1 << i) != 0).map(|i| (i + 1).to_string()).collect();
    if slots.is_empty() { "receiver only".to_string() } else { format!("slots {}", slots.join(",")) }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Whatever can produce fingerprint material for a requested binding:
/// the live receivers (`fingerprint::Fingerprint`) or a test double.
pub trait DongleSource {
    /// Receivers currently readable (`DONGLE_*` mask).
    fn plugged(&self) -> u8;
    /// Material for `dongles` bound to receiver slots `bind`, or why not.
    fn material(&self, dongles: u8, bind: u8) -> Result<Secret, String>;
}

/// Material plus its public description, ready to wrap a slot.
#[derive(Clone, Debug)]
pub struct Dongle {
    pub material: Secret,
    pub dongles: u8,
    pub nkeys: u8,
    pub bind: u8,
}

/// Recipe for one keyslot.
pub struct SlotSpec<'a> {
    pub kind: Kind,
    pub dongle: Option<&'a Dongle>,
    pub pass: Option<&'a [u8]>,
    pub argon: Argon,
}

impl<'a> SlotSpec<'a> {
    pub fn dongle(d: &'a Dongle) -> Self {
        SlotSpec { kind: Kind::Dongle, dongle: Some(d), pass: None, argon: ARGON_NONE }
    }
    pub fn pass(pass: &'a [u8]) -> Self {
        SlotSpec { kind: Kind::Pass, dongle: None, pass: Some(pass), argon: ARGON_DEFAULT }
    }
    pub fn dongle_pass(d: &'a Dongle, pass: &'a [u8]) -> Self {
        SlotSpec { kind: Kind::DonglePass, dongle: Some(d), pass: Some(pass), argon: ARGON_DEFAULT }
    }
    #[allow(dead_code)]
    pub fn with_argon(mut self, a: Argon) -> Self {
        self.argon = a;
        self
    }
}

/// Public one-way tag of a fingerprint (separate salt and info from the KEK).
pub fn kid(material: &[u8]) -> [u8; 8] {
    let hk = Hkdf::<Sha256>::new(Some(b"uniseal-kid-v1"), material);
    let mut out = [0u8; 8];
    hk.expand(b"uniseal-kid", &mut out).expect("hkdf expand");
    out
}

fn kek(kind: Kind, salt: &[u8; 16], material: Option<&[u8]>, pass_hash: Option<&[u8; 32]>) -> Key {
    let mut ikm: Secret = Zeroizing::new(Vec::new());
    if let Some(p) = pass_hash {
        ikm.extend_from_slice(p);
    }
    if let Some(m) = material {
        ikm.extend_from_slice(m);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut k: Key = Zeroizing::new([0u8; 32]);
    let info = [b"uniseal-kek-v1" as &[u8], &[kind as u8]].concat();
    hk.expand(&info, &mut k[..]).expect("hkdf expand");
    k
}

fn argon(pass: &[u8], salt: &[u8; 16], a: Argon) -> Result<Zeroizing<[u8; 32]>, Error> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(a.m_kib, a.t, a.p, Some(32)).map_err(|_| Error::Argon)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass, salt, &mut out[..])
        .map_err(|_| Error::Argon)?;
    Ok(out)
}

fn cipher(k: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(&k[..]).expect("32-byte key")
}

fn xnonce(n: &[u8; 24]) -> XNonce {
    XNonce::try_from(&n[..]).expect("24-byte nonce")
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Slot {
    pub kind: Kind,
    pub dongles: u8,
    pub nkeys: u8,
    pub bind: u8,
    pub kid: [u8; 8],
    pub argon: Argon,
    salt: [u8; 16],
    nonce: [u8; 24],
    wrapped: [u8; 48],
}

impl Slot {
    fn header(&self) -> [u8; SLOT_AAD] {
        let mut h = [0u8; SLOT_AAD];
        h[0] = self.kind as u8;
        h[1] = self.dongles;
        h[2] = self.nkeys;
        h[3] = self.bind;
        h[4..12].copy_from_slice(&self.kid);
        h[12..28].copy_from_slice(&self.salt);
        h[28..32].copy_from_slice(&self.argon.m_kib.to_be_bytes());
        h[32..36].copy_from_slice(&self.argon.t.to_be_bytes());
        h[36..40].copy_from_slice(&self.argon.p.to_be_bytes());
        h
    }

    fn aad(&self) -> Vec<u8> {
        [MAGIC as &[u8], &self.header()].concat()
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.wrapped);
    }

    fn read(b: &[u8]) -> Result<Slot, Error> {
        debug_assert_eq!(b.len(), SLOT_LEN);
        let kind = Kind::from_u8(b[0]).ok_or_else(|| Error::Corrupt("unknown keyslot kind".into()))?;
        let u32be = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().expect("4 bytes"));
        let mut s = Slot {
            kind,
            dongles: b[1],
            nkeys: b[2],
            bind: b[3],
            kid: [0; 8],
            argon: Argon { m_kib: u32be(28), t: u32be(32), p: u32be(36) },
            salt: [0; 16],
            nonce: [0; 24],
            wrapped: [0; 48],
        };
        s.kid.copy_from_slice(&b[4..12]);
        s.salt.copy_from_slice(&b[12..28]);
        s.nonce.copy_from_slice(&b[40..64]);
        s.wrapped.copy_from_slice(&b[64..112]);
        Ok(s)
    }

    pub fn needs_dongle(&self) -> bool {
        self.kind.needs_dongle()
    }
    pub fn needs_pass(&self) -> bool {
        self.kind.needs_pass()
    }

    pub fn describe(&self) -> String {
        let dongle = || {
            let where_ = if self.dongles & DONGLE_TI != 0 { format!(" · {}", bind_label(self.bind)) } else { String::new() };
            format!("dongle {}{} · {} rec.", dongles_label(self.dongles), where_, self.nkeys)
        };
        let pass = || format!("Argon2id {} MiB t={}", self.argon.m_kib / 1024, self.argon.t);
        match self.kind {
            Kind::Dongle => dongle(),
            Kind::Pass => format!("passphrase ({})", pass()),
            Kind::DonglePass => format!("{} + PIN ({})", dongle(), pass()),
        }
    }

    /// Material the plugged receivers give for this slot, or why they cannot.
    pub fn check_dongle(&self, src: Option<&dyn DongleSource>) -> Result<Option<Secret>, String> {
        if !self.needs_dongle() {
            return Ok(None);
        }
        let src = src.ok_or_else(|| format!("needs dongle {}, none readable", dongles_label(self.dongles)))?;
        let m = src.material(self.dongles, self.bind)?;
        if kid(&m) != self.kid {
            return Err(format!(
                "dongle {} kid {} expected, got {} (device re-paired?)",
                dongles_label(self.dongles),
                hex(&self.kid),
                hex(&kid(&m))
            ));
        }
        Ok(Some(m))
    }

    fn wrap(fk: &Key, spec: &SlotSpec, rng: &mut Rng) -> Result<Slot, Error> {
        let dongle = match (spec.kind.needs_dongle(), spec.dongle) {
            (true, None) => return Err(Error::BadSpec("this keyslot kind needs dongle material")),
            (true, Some(d)) if d.material.is_empty() => return Err(Error::BadSpec("empty dongle material")),
            (true, d) => d,
            (false, _) => None,
        };
        let pass = match (spec.kind.needs_pass(), spec.pass) {
            (true, None) => return Err(Error::BadSpec("this keyslot kind needs a passphrase")),
            (true, Some(&[])) => return Err(Error::BadSpec("empty passphrase")),
            (true, p) => p,
            (false, _) => None,
        };
        let mut s = Slot {
            kind: spec.kind,
            dongles: dongle.map(|d| d.dongles).unwrap_or(0),
            nkeys: dongle.map(|d| d.nkeys).unwrap_or(0),
            bind: dongle.map(|d| d.bind).unwrap_or(0),
            kid: dongle.map(|d| kid(&d.material)).unwrap_or([0; 8]),
            argon: if pass.is_some() { spec.argon } else { ARGON_NONE },
            salt: [0; 16],
            nonce: [0; 24],
            wrapped: [0; 48],
        };
        rng(&mut s.salt)?;
        rng(&mut s.nonce)?;
        let ph = match pass {
            Some(p) => Some(argon(p, &s.salt, s.argon)?),
            None => None,
        };
        let k = kek(s.kind, &s.salt, dongle.map(|d| d.material.as_slice()), ph.as_deref());
        let ct = cipher(&k)
            .encrypt(&xnonce(&s.nonce), Payload { msg: &fk[..], aad: &s.aad() })
            .map_err(|_| Error::Corrupt("wrap".into()))?;
        s.wrapped.copy_from_slice(&ct);
        Ok(s)
    }

    fn unwrap(&self, material: Option<&[u8]>, pass: Option<&[u8]>) -> Result<Key, Error> {
        let material = if self.needs_dongle() {
            Some(material.ok_or(Error::BadSpec("keyslot needs dongle material"))?)
        } else {
            None
        };
        let ph = if self.needs_pass() {
            Some(argon(pass.ok_or(Error::BadSpec("keyslot needs a passphrase"))?, &self.salt, self.argon)?)
        } else {
            None
        };
        let k = kek(self.kind, &self.salt, material, ph.as_deref());
        let pt = Zeroizing::new(
            cipher(&k)
                .decrypt(&xnonce(&self.nonce), Payload { msg: &self.wrapped, aad: &self.aad() })
                .map_err(|_| Error::WrongKey)?,
        );
        let mut fk: Key = Zeroizing::new([0u8; 32]);
        fk.copy_from_slice(&pt);
        Ok(fk)
    }
}

/// The keyslots of a vault; the body streams separately.
#[derive(Debug, Clone)]
pub struct Header {
    pub slots: Vec<Slot>,
}

impl Header {
    /// Parse from the start of a vault; returns the header and its length.
    pub fn parse(blob: &[u8]) -> Result<(Header, usize), Error> {
        if blob.len() < 8 || &blob[..8] != MAGIC {
            return Err(Error::NotVault);
        }
        let n = *blob.get(8).ok_or(Error::Truncated)? as usize;
        if n == 0 || n > MAX_SLOTS {
            return Err(Error::Corrupt("keyslot count".into()));
        }
        let end = 9 + n * SLOT_LEN;
        if blob.len() < end {
            return Err(Error::Truncated);
        }
        let mut slots = Vec::with_capacity(n);
        for i in 0..n {
            slots.push(Slot::read(&blob[9 + i * SLOT_LEN..9 + (i + 1) * SLOT_LEN])?);
        }
        Ok((Header { slots }, end))
    }

    /// Read exactly the header, leaving `r` positioned at the body.
    pub fn read(r: &mut dyn Read) -> Result<Header, Error> {
        let mut head = [0u8; 9];
        let got = read_full(r, &mut head)?;
        if got < 8 || &head[..8] != MAGIC {
            return Err(Error::NotVault);
        }
        if got < 9 {
            return Err(Error::Truncated);
        }
        let n = usize::from(head[8]);
        if n == 0 || n > MAX_SLOTS {
            return Err(Error::Corrupt("keyslot count".into()));
        }
        let mut all = head.to_vec();
        all.resize(9 + n * SLOT_LEN, 0);
        if read_full(r, &mut all[9..])? < n * SLOT_LEN {
            return Err(Error::Truncated);
        }
        Header::parse(&all).map(|(h, _)| h)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(self.slots.len() as u8);
        for s in &self.slots {
            s.write(&mut out);
        }
        out
    }

    /// Unwrap the file key with slot `i`.
    pub fn open_slot(&self, i: usize, material: Option<&[u8]>, pass: Option<&[u8]>) -> Result<Key, Error> {
        self.slots.get(i).ok_or(Error::NoSuchSlot)?.unwrap(material, pass)
    }

    /// Try every slot in order. `ask` is called for slots that need a
    /// passphrase (return `None` to skip). Errors list why each slot failed.
    pub fn unlock_any(
        &self,
        src: Option<&dyn DongleSource>,
        ask: &mut dyn FnMut(usize, &Slot) -> Option<Secret>,
    ) -> Result<(usize, Key), Error> {
        let mut reasons = Vec::new();
        for (i, s) in self.slots.iter().enumerate() {
            let tag = format!("slot {i} ({})", s.describe());
            let material = match s.check_dongle(src) {
                Ok(m) => m,
                Err(r) => {
                    reasons.push(format!("{tag}: {r}"));
                    continue;
                }
            };
            let pass = if s.needs_pass() {
                match ask(i, s) {
                    Some(p) => Some(p),
                    None => {
                        reasons.push(format!("{tag}: no passphrase given"));
                        continue;
                    }
                }
            } else {
                None
            };
            match s.unwrap(material.as_deref().map(|m| m.as_slice()), pass.as_deref().map(|p| p.as_slice())) {
                Ok(k) => return Ok((i, k)),
                Err(Error::WrongKey) => reasons.push(format!(
                    "{tag}: {}",
                    if s.needs_pass() { "wrong passphrase" } else { "dongle material mismatch" }
                )),
                Err(e) => return Err(e),
            }
        }
        Err(Error::NoUsableSlot(reasons))
    }

    pub fn add_slot(&mut self, fk: &Key, spec: &SlotSpec, rng: &mut Rng) -> Result<usize, Error> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::TooManySlots);
        }
        self.slots.push(Slot::wrap(fk, spec, rng)?);
        Ok(self.slots.len() - 1)
    }

    pub fn remove_slot(&mut self, i: usize) -> Result<(), Error> {
        if i >= self.slots.len() {
            return Err(Error::NoSuchSlot);
        }
        if self.slots.len() == 1 {
            return Err(Error::LastSlot);
        }
        self.slots.remove(i);
        Ok(())
    }
}

/// Fill `buf` unless EOF comes first; returns the bytes read.
fn read_full(r: &mut dyn Read, buf: &mut [u8]) -> Result<usize, Error> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(n)
}

/// Reader with one byte of lookahead, to learn whether a chunk is the last.
struct Chunker<'a> {
    src: &'a mut dyn Read,
    carry: Option<u8>,
}

impl Chunker<'_> {
    /// Fill `buf` as far as possible; `last` tells whether EOF follows.
    fn next(&mut self, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        let mut n = 0;
        if let Some(b) = self.carry.take() {
            buf[0] = b;
            n = 1;
        }
        n += read_full(self.src, &mut buf[n..])?;
        if n < buf.len() {
            return Ok((n, true));
        }
        let mut peek = [0u8; 1];
        if read_full(self.src, &mut peek)? == 0 {
            Ok((n, true))
        } else {
            self.carry = Some(peek[0]);
            Ok((n, false))
        }
    }
}

fn chunk_nonce(prefix: &[u8; PREFIX], i: u32, last: bool) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..PREFIX].copy_from_slice(prefix);
    n[PREFIX..23].copy_from_slice(&i.to_be_bytes());
    n[23] = last as u8;
    n
}

/// Encrypt `src` under a fresh file key wrapped in `specs`, writing the
/// whole vault to `dst`. Returns the header and the plaintext length.
pub fn seal(src: &mut dyn Read, dst: &mut dyn Write, specs: &[SlotSpec], rng: &mut Rng) -> Result<(Header, u64), Error> {
    if specs.is_empty() {
        return Err(Error::BadSpec("at least one keyslot is required"));
    }
    if specs.len() > MAX_SLOTS {
        return Err(Error::TooManySlots);
    }
    let mut fk: Key = Zeroizing::new([0u8; 32]);
    rng(&mut fk[..])?;
    let mut slots = Vec::with_capacity(specs.len());
    for spec in specs {
        slots.push(Slot::wrap(&fk, spec, rng)?);
    }
    let header = Header { slots };
    dst.write_all(&header.to_bytes())?;
    let mut prefix = [0u8; PREFIX];
    rng(&mut prefix)?;
    dst.write_all(&prefix)?;
    let c = cipher(&fk);
    let mut buf: Secret = Zeroizing::new(vec![0u8; CHUNK]);
    let mut chunker = Chunker { src, carry: None };
    let mut total = 0u64;
    let mut i = 0u32;
    loop {
        let (n, last) = chunker.next(&mut buf)?;
        let ct = c
            .encrypt(&xnonce(&chunk_nonce(&prefix, i, last)), Payload { msg: &buf[..n], aad: MAGIC })
            .map_err(|_| Error::Corrupt("encrypt".into()))?;
        dst.write_all(&ct)?;
        total += n as u64;
        if last {
            break;
        }
        i = i.checked_add(1).ok_or_else(|| Error::Corrupt("too many chunks".into()))?;
    }
    dst.flush()?;
    Ok((header, total))
}

/// Decrypt the body (everything after the header) with an unwrapped file
/// key, writing the plaintext to `dst`. Returns the plaintext length.
pub fn open_body(src: &mut dyn Read, dst: &mut dyn Write, fk: &Key) -> Result<u64, Error> {
    let mut prefix = [0u8; PREFIX];
    if read_full(src, &mut prefix)? != PREFIX {
        return Err(Error::Truncated);
    }
    let c = cipher(fk);
    let mut buf = vec![0u8; CHUNK + TAG];
    let mut chunker = Chunker { src, carry: None };
    let mut total = 0u64;
    let mut i = 0u32;
    loop {
        let (n, last) = chunker.next(&mut buf)?;
        if n < TAG {
            return Err(Error::Truncated);
        }
        let pt = Zeroizing::new(
            c.decrypt(&xnonce(&chunk_nonce(&prefix, i, last)), Payload { msg: &buf[..n], aad: MAGIC })
                .map_err(|_| Error::Corrupt(format!("chunk {i} rejected (damaged, reordered or truncated)")))?,
        );
        dst.write_all(&pt)?;
        total += pt.len() as u64;
        if last {
            break;
        }
        i = i.checked_add(1).ok_or_else(|| Error::Corrupt("too many chunks".into()))?;
    }
    dst.flush()?;
    Ok(total)
}

/// In-memory convenience: whole vault as bytes.
#[cfg(test)]
pub fn seal_bytes(data: &[u8], specs: &[SlotSpec], rng: &mut Rng) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    seal(&mut &data[..], &mut out, specs, rng)?;
    Ok(out)
}

/// In-memory convenience: plaintext of `blob` given the file key.
#[cfg(test)]
pub fn open_bytes(blob: &[u8], fk: &Key) -> Result<Secret, Error> {
    let (_, n) = Header::parse(blob)?;
    let mut out = Vec::new();
    open_body(&mut &blob[n..], &mut out, fk)?;
    Ok(Zeroizing::new(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: Argon = Argon { m_kib: 8, t: 1, p: 1 };
    // Synthetic material (fake serials): never paste a real dongle read here.
    const MAT: &[u8] = b"uniseal-fp-v1\x01\x05\xc5\x2b\x11\x22\x33\x44\x02\x01\x40\x4d\x04\xaa\xbb\xcc\xdd\x00\x03\x40\x8a\x04\x01\x02\x03\x04\x00";

    /// Test double: plugged TI with slots 1 and 3; material is MAT plus the
    /// requested (dongles, bind) so different bindings differ.
    struct Fake {
        plugged: u8,
    }

    impl DongleSource for Fake {
        fn plugged(&self) -> u8 {
            self.plugged
        }
        fn material(&self, dongles: u8, bind: u8) -> Result<Secret, String> {
            if dongles & !self.plugged != 0 {
                return Err(format!("needs dongle {}, plugged {}", dongles_label(dongles), dongles_label(self.plugged)));
            }
            if bind & !0b101 != 0 {
                return Err("device slot missing".into());
            }
            let mut m = Zeroizing::new(MAT.to_vec());
            m.push(dongles);
            m.push(bind);
            Ok(m)
        }
    }

    fn fake() -> Fake {
        Fake { plugged: DONGLE_TI }
    }

    fn ti() -> Dongle {
        Dongle { material: fake().material(DONGLE_TI, 0b101).unwrap(), dongles: DONGLE_TI, nkeys: 2, bind: 0b101 }
    }

    fn det_rng() -> impl FnMut(&mut [u8]) -> Result<(), Error> {
        let mut c = 0u8;
        move |b| {
            for x in b.iter_mut() {
                *x = c;
                c = c.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn no_pass(_: usize, _: &Slot) -> Option<Secret> {
        None
    }

    fn open_with(blob: &[u8], src: Option<&dyn DongleSource>, pass: Option<&[u8]>) -> Result<(usize, Secret), Error> {
        let (h, _) = Header::parse(blob)?;
        let (i, fk) = h.unlock_any(src, &mut |_, _| pass.map(|p| Zeroizing::new(p.to_vec())))?;
        Ok((i, open_bytes(blob, &fk)?))
    }

    #[test]
    fn dongle_roundtrip_and_rejections() {
        let data = b"payload bound to a TI receiver";
        let d = ti();
        let blob = seal_bytes(data, &[SlotSpec::dongle(&d)], &mut os_rng).unwrap();
        assert_eq!(&blob[..8], MAGIC);
        let (i, pt) = open_with(&blob, Some(&fake()), None).unwrap();
        assert_eq!(i, 0);
        assert_eq!(&pt[..], data);
        assert_ne!(seal_bytes(data, &[SlotSpec::dongle(&d)], &mut os_rng).unwrap(), blob, "random file key");
        assert_eq!(Header::parse(&blob).unwrap().0.slots[0].describe(), "dongle TI · slots 1,3 · 2 rec.");

        // Wrong receiver, missing receiver, re-paired device (different material).
        let nano_only = Fake { plugged: DONGLE_NANO };
        match open_with(&blob, Some(&nano_only), None) {
            Err(Error::NoUsableSlot(r)) => assert!(r[0].contains("needs dongle TI"), "{r:?}"),
            e => panic!("{e:?}"),
        }
        assert!(matches!(open_with(&blob, None, None), Err(Error::NoUsableSlot(_))));
        struct Repaired;
        impl DongleSource for Repaired {
            fn plugged(&self) -> u8 {
                DONGLE_TI
            }
            fn material(&self, _: u8, _: u8) -> Result<Secret, String> {
                Ok(Zeroizing::new(b"something else".to_vec()))
            }
        }
        match open_with(&blob, Some(&Repaired), None) {
            Err(Error::NoUsableSlot(r)) => assert!(r[0].contains("re-paired"), "{r:?}"),
            e => panic!("{e:?}"),
        }

        // Tampering: body, wrapped key, slot header (AAD).
        let (h, _) = Header::parse(&blob).unwrap();
        let (_, fk) = h.unlock_any(Some(&fake()), &mut no_pass).unwrap();
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(matches!(open_bytes(&bad, &fk), Err(Error::Corrupt(_))), "body tamper");
        let mut bad = blob.clone();
        bad[9 + 100] ^= 1;
        assert!(matches!(open_with(&bad, Some(&fake()), None), Err(Error::NoUsableSlot(_))), "wrapped key tamper");
        let mut bad = blob.clone();
        bad[9 + 3] ^= 1;
        assert!(matches!(open_with(&bad, Some(&fake()), None), Err(Error::NoUsableSlot(_))), "bind byte is AAD");

        assert_eq!(Header::parse(&blob[..50]).unwrap_err(), Error::Truncated);
        assert_eq!(Header::parse(b"NVLT4\0\0\0old-format").unwrap_err(), Error::NotVault);
        assert_eq!(Header::parse(b"KEYFOB5\0old-format").unwrap_err(), Error::NotVault);
        assert_eq!(Header::parse(b"").unwrap_err(), Error::NotVault);
        let empty = seal_bytes(b"", &[SlotSpec::dongle(&d)], &mut os_rng).unwrap();
        assert!(open_with(&empty, Some(&fake()), None).unwrap().1.is_empty());
    }

    #[test]
    fn streaming_chunks_and_truncation() {
        let d = ti();
        // 2.5 chunks, then exactly 2 chunks (last chunk full-size).
        for len in [CHUNK * 2 + CHUNK / 2, CHUNK * 2, 1, CHUNK - 1, CHUNK + 1] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            let mut blob = Vec::new();
            let (h, n) = seal(&mut &data[..], &mut blob, &[SlotSpec::dongle(&d)], &mut os_rng).unwrap();
            assert_eq!(n as usize, len);
            let (_, fk) = h.unlock_any(Some(&fake()), &mut no_pass).unwrap();
            let (_, hlen) = Header::parse(&blob).unwrap();
            let mut out = Vec::new();
            assert_eq!(open_body(&mut &blob[hlen..], &mut out, &fk).unwrap() as usize, len);
            assert_eq!(out, data);
            let chunks = len.div_ceil(CHUNK).max(1);
            assert_eq!(blob.len(), hlen + PREFIX + len + chunks * TAG);
            if chunks > 1 {
                // Cut at a chunk boundary: the "last" flag catches it.
                let cut = hlen + PREFIX + CHUNK + TAG;
                let mut out = Vec::new();
                let e = open_body(&mut &blob[hlen..cut], &mut out, &fk).unwrap_err();
                assert!(matches!(e, Error::Corrupt(_)), "{e}");
                // Swap two chunks: the counter catches it.
                let mut swapped = blob.clone();
                if len < 2 * CHUNK {
                    continue;
                }
                let a = hlen + PREFIX;
                let b = a + CHUNK + TAG;
                let (first, second) = (swapped[a..b].to_vec(), swapped[b..b + CHUNK + TAG].to_vec());
                swapped[a..b].copy_from_slice(&second);
                swapped[b..b + CHUNK + TAG].copy_from_slice(&first);
                assert!(matches!(open_bytes(&swapped, &fk), Err(Error::Corrupt(_))));
            }
            // Cut mid-chunk.
            let mut out = Vec::new();
            let e = open_body(&mut &blob[hlen..blob.len() - 5], &mut out, &fk).unwrap_err();
            assert!(matches!(e, Error::Corrupt(_) | Error::Truncated), "{e}");
        }
    }

    #[test]
    fn header_read_from_stream() {
        let d = ti();
        let blob = seal_bytes(b"stream me", &[SlotSpec::dongle(&d), SlotSpec::pass(b"x").with_argon(TINY)], &mut os_rng).unwrap();
        let mut cur = &blob[..];
        let h = Header::read(&mut cur).unwrap();
        assert_eq!(h.slots.len(), 2);
        let (_, fk) = h.unlock_any(Some(&fake()), &mut no_pass).unwrap();
        let mut out = Vec::new();
        open_body(&mut cur, &mut out, &fk).unwrap();
        assert_eq!(out, b"stream me");
        assert_eq!(Header::read(&mut &b"UNISEAL1\x01"[..]).unwrap_err(), Error::Truncated);
        assert_eq!(Header::read(&mut &b"nope"[..]).unwrap_err(), Error::NotVault);
    }

    #[test]
    fn passphrase_and_second_factor() {
        let d = ti();
        let specs = [SlotSpec::dongle_pass(&d, b"1234").with_argon(TINY), SlotSpec::pass(b"correct horse").with_argon(TINY)];
        let blob = seal_bytes(b"two factors", &specs, &mut os_rng).unwrap();
        let (h, _) = Header::parse(&blob).unwrap();
        assert_eq!(h.slots[0].kind, Kind::DonglePass);
        assert_eq!(h.slots[1].kind, Kind::Pass);
        assert_eq!(h.slots[1].argon, TINY);

        let (i, pt) = open_with(&blob, Some(&fake()), Some(b"1234")).unwrap();
        assert_eq!((i, &pt[..]), (0, &b"two factors"[..]));
        assert!(matches!(open_with(&blob, Some(&fake()), None), Err(Error::NoUsableSlot(_))), "dongle alone refused");
        let (i, _) = open_with(&blob, None, Some(b"correct horse")).unwrap();
        assert_eq!(i, 1, "recovery passphrase opens without dongles");
        match open_with(&blob, Some(&fake()), Some(b"nope")) {
            Err(Error::NoUsableSlot(r)) => {
                assert_eq!(r.len(), 2);
                assert!(r.iter().all(|s| s.contains("wrong passphrase")), "{r:?}");
            }
            e => panic!("{e:?}"),
        }
        assert!(seal_bytes(b"x", &[SlotSpec::pass(b"")], &mut os_rng).is_err());
    }

    #[test]
    fn slot_management() {
        let d = ti();
        let blob = seal_bytes(b"data", &[SlotSpec::dongle(&d)], &mut os_rng).unwrap();
        let (mut h, hlen) = Header::parse(&blob).unwrap();
        let (_, fk) = h.unlock_any(Some(&fake()), &mut no_pass).unwrap();
        assert_eq!(h.add_slot(&fk, &SlotSpec::pass(b"rescue").with_argon(TINY), &mut os_rng).unwrap(), 1);
        let mut rebuilt = h.to_bytes();
        rebuilt.extend_from_slice(&blob[hlen..]);
        let (i, pt) = open_with(&rebuilt, None, Some(b"rescue")).unwrap();
        assert_eq!((i, &pt[..]), (1, &b"data"[..]), "added slot wraps the same file key");
        h.remove_slot(0).unwrap();
        assert_eq!(h.remove_slot(0), Err(Error::LastSlot));
        assert_eq!(h.remove_slot(5), Err(Error::NoSuchSlot));
        assert!(matches!(h.unlock_any(Some(&fake()), &mut no_pass), Err(Error::NoUsableSlot(_))), "dongle slot gone");
        for _ in 0..MAX_SLOTS - 1 {
            h.add_slot(&fk, &SlotSpec::dongle(&d), &mut os_rng).unwrap();
        }
        assert_eq!(h.add_slot(&fk, &SlotSpec::dongle(&d), &mut os_rng).unwrap_err(), Error::TooManySlots);
    }

    #[test]
    fn binding_subset() {
        // Bound to the receiver only: a fake that lost slot 3 still opens it.
        let recv = Dongle { material: fake().material(DONGLE_TI, 0).unwrap(), dongles: DONGLE_TI, nkeys: 0, bind: 0 };
        let blob = seal_bytes(b"receiver only", &[SlotSpec::dongle(&recv)], &mut os_rng).unwrap();
        assert_eq!(Header::parse(&blob).unwrap().0.slots[0].describe(), "dongle TI · receiver only · 0 rec.");
        assert_eq!(&open_with(&blob, Some(&fake()), None).unwrap().1[..], b"receiver only");
        // Bound to slots 1 and 3 while only slot 1 exists later: refused with a reason.
        struct Lost;
        impl DongleSource for Lost {
            fn plugged(&self) -> u8 {
                DONGLE_TI
            }
            fn material(&self, d: u8, bind: u8) -> Result<Secret, String> {
                if bind & 0b100 != 0 { Err("device in slot 3 missing".into()) } else { fake().material(d, bind) }
            }
        }
        let d = ti();
        let full = seal_bytes(b"x", &[SlotSpec::dongle(&d)], &mut os_rng).unwrap();
        match open_with(&full, Some(&Lost), None) {
            Err(Error::NoUsableSlot(r)) => assert!(r[0].contains("slot 3 missing"), "{r:?}"),
            e => panic!("{e:?}"),
        }
        assert_eq!(&open_with(&blob, Some(&Lost), None).unwrap().1[..], b"receiver only");
    }

    /// Known-answer test: any change to the KDFs, the AAD, the layout, the
    /// chunking or the nonce order silently bricks every existing vault.
    /// Regenerate the expected bytes only for a deliberate format bump.
    #[test]
    fn known_answer() {
        let d = ti();
        let specs = [SlotSpec::dongle(&d), SlotSpec::pass(b"hunter2").with_argon(TINY)];
        let blob = seal_bytes(b"known answer", &specs, &mut det_rng()).unwrap();
        let got = hex(&blob);
        assert_eq!(hex(&kid(&d.material)), "D76B23038ADAC887");
        assert_eq!(
            got,
            "554E495345414C310201010205D76B23038ADAC887202122232425262728292A\
             2B2C2D2E2F000000000000000000000000303132333435363738393A3B3C3D3E\
             3F4041424344454647B7EDDE412F52AEAB3DEBC5C6D4947E4034931FD188F463\
             EFB8AB13D23DD24F727384A1F7E8877BFB522FD9FCA65523C902000000000000\
             000000000048494A4B4C4D4E4F50515253545556570000000800000001000000\
             0158595A5B5C5D5E5F606162636465666768696A6B6C6D6E6FD7EE6303C4685B\
             A85E7D72E22AE468E9800FFC9D51A7829832E754F3B94C590F37FB9A8872B468\
             A3936636638E7950D6707172737475767778797A7B7C7D7E7F8081826F9B5DAA\
             76622E9F53B2C0B038B4E613F921245E8E3D9DB225031E1D"
        );
    }
}
