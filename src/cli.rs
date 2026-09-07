//! CLI: `id`, `lock`, `unlock`, `info`, `addkey`, `delkey`, `gui`.

use crate::fingerprint::{self, Fingerprint, FpError};
use crate::fsio::{self, AtomicWriter, HashReader, HashSink};
use crate::vault::{self, Dongle, DongleSource, Header, Kind, Secret, Slot, SlotSpec};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "uniseal", version, about = "File vault bound to Logitech Unifying receivers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the live receiver fingerprint, its grade and key id
    Id,
    /// Lock a file into <file>.vault (possession-only keyslot by default)
    Lock {
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        /// Require a PIN together with the dongles (real second factor)
        #[arg(long)]
        pin: bool,
        /// Add a passphrase-only recovery keyslot (opens without dongles)
        #[arg(long)]
        recovery: bool,
        /// Receiver slots to bind: `all` (default), `receiver`, or `1,3`
        #[arg(long, default_value = "all")]
        bind: String,
        /// Overwrite an existing destination
        #[arg(long)]
        force: bool,
    },
    /// Unlock a .vault (strips the extension; never overwrites silently)
    Unlock {
        file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// List the keyslots of a vault and check them against the plugged dongles
    Info { file: PathBuf },
    /// Add a keyslot to a vault (opens it first with any existing slot)
    Addkey {
        file: PathBuf,
        /// Dongles + PIN keyslot
        #[arg(long)]
        pin: bool,
        /// Passphrase-only recovery keyslot
        #[arg(long)]
        recovery: bool,
        /// Possession-only keyslot for the currently plugged dongles
        #[arg(long)]
        dongle: bool,
        /// Receiver slots to bind for --pin / --dongle
        #[arg(long, default_value = "all")]
        bind: String,
    },
    /// Remove keyslot N from a vault (refuses to remove the last one)
    Delkey { file: PathBuf, slot: usize },
    /// Open the SDL2 vault window, optionally with a file preselected
    Gui { file: Option<PathBuf> },
}

fn prompt(label: &str) -> Result<Secret, String> {
    let s = rpassword::prompt_password(format!("{label}: ")).map_err(|e| format!("passphrase prompt: {e}"))?;
    Ok(Zeroizing::new(s.into_bytes()))
}

fn prompt_new(label: &str) -> Result<Secret, String> {
    let a = prompt(label)?;
    if a.is_empty() {
        return Err("empty passphrase refused".into());
    }
    let b = prompt(&format!("{label} (again)"))?;
    if a != b {
        return Err("passphrases differ".into());
    }
    Ok(a)
}

fn read_dongles() -> Result<Fingerprint, FpError> {
    let api = hidapi::HidApi::new().map_err(|e| FpError::Unresponsive(e.to_string()))?;
    fingerprint::collect(&api)
}

/// Fingerprint if readable, else the reason (unlock can still use passphrase slots).
fn dongles_opt() -> (Option<Fingerprint>, Option<String>) {
    match read_dongles() {
        Ok(fp) => {
            println!("  {}", fp.summary());
            (Some(fp), None)
        }
        Err(e) => (None, Some(e.to_string())),
    }
}

fn open_vault(path: &Path) -> Result<(File, Header), String> {
    let mut f = File::open(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let h = Header::read(&mut f).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((f, h))
}

/// Open any keyslot, prompting for a passphrase at most once.
fn open_any(h: &Header, fp: Option<&Fingerprint>) -> Result<(usize, vault::Key), String> {
    let mut cached: Option<Secret> = None;
    let mut ask = |i: usize, s: &Slot| -> Option<Secret> {
        if cached.is_none() {
            let label = if s.kind == Kind::DonglePass { "PIN" } else { "passphrase" };
            cached = prompt(&format!("slot {i} {label}")).ok().filter(|p| !p.is_empty());
        }
        cached.clone()
    };
    h.unlock_any(fp.map(|f| f as &dyn DongleSource), &mut ask).map_err(|e| e.to_string())
}

/// Dongle material for a lock/addkey, with the grade warning.
fn dongle_for(fp: &Fingerprint, bind: &str, pin: bool) -> Result<Dongle, String> {
    let d = fp.dongle(fingerprint::parse_bind(bind)?)?;
    if d.nkeys == 0 && !pin {
        println!("  warning: no pairing record in this binding, the keyslot rests on serials alone; consider --pin");
    }
    println!("  binding: {} · {} · {} rec.", vault::dongles_label(d.dongles), vault::bind_label(d.bind), d.nkeys);
    Ok(d)
}

fn cmd_lock(file: &Path, out: Option<PathBuf>, pin: bool, recovery: bool, bind: &str, force: bool) -> Result<(), String> {
    let (fp, why) = dongles_opt();
    let dongle = match &fp {
        Some(fp) => Some(dongle_for(fp, bind, pin)?),
        None => None,
    };
    let pin_pass = if pin { Some(prompt_new("PIN (with dongles)")?) } else { None };
    let rec_pass = if recovery { Some(prompt_new("recovery passphrase (no dongles)")?) } else { None };
    let mut specs = Vec::new();
    match (&dongle, &pin_pass) {
        (Some(d), Some(p)) => specs.push(SlotSpec::dongle_pass(d, p)),
        (Some(d), None) => specs.push(SlotSpec::dongle(d)),
        (None, _) if rec_pass.is_some() => println!("  no dongles ({}): passphrase-only vault", why.unwrap_or_default()),
        (None, _) => return Err(why.unwrap_or_default()),
    }
    if let Some(p) = &rec_pass {
        specs.push(SlotSpec::pass(p));
    }
    let dest = out.unwrap_or_else(|| fsio::vault_path(file));
    let mut src = HashReader::new(File::open(file).map_err(|e| format!("read {}: {e}", file.display()))?);
    let mut w = AtomicWriter::create(&dest, force).map_err(|e| e.to_string())?;
    let (header, len) = vault::seal(&mut src, &mut w, &specs, &mut vault::os_rng).map_err(|e| e.to_string())?;
    w.commit().map_err(|e| e.to_string())?;
    let digest = src.digest();
    // Verify before reporting success: every slot must unwrap the key, and the
    // body must decrypt back to the exact plaintext.
    let (mut f, check) = open_vault(&dest)?;
    let mut keys = Vec::new();
    for (i, spec) in specs.iter().enumerate() {
        match check.open_slot(i, spec.dongle.map(|d| d.material.as_slice()), spec.pass) {
            Ok(k) => keys.push(k),
            Err(e) => {
                let _ = std::fs::remove_file(&dest);
                return Err(format!("self-check failed on slot {i} ({e}), vault removed"));
            }
        }
    }
    let mut sink = HashSink::default();
    let ok = vault::open_body(&mut f, &mut sink, &keys[0]).is_ok() && sink.digest() == digest;
    if !ok {
        let _ = std::fs::remove_file(&dest);
        return Err("self-check failed on the body, vault removed".into());
    }
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    println!("  locked: {} ({len} -> {size} bytes)", dest.display());
    for (i, s) in header.slots.iter().enumerate() {
        println!("  slot {i}: {}", s.describe());
    }
    Ok(())
}

fn cmd_unlock(file: &Path, out: Option<PathBuf>, force: bool) -> Result<(), String> {
    let (mut f, h) = open_vault(file)?;
    let (fp, why) = dongles_opt();
    if let Some(w) = &why {
        println!("  dongles unreadable: {w}");
    }
    let (i, fk) = open_any(&h, fp.as_ref())?;
    let dest = out.unwrap_or_else(|| fsio::open_path(file));
    let mut w = AtomicWriter::create(&dest, force).map_err(|e| e.to_string())?;
    let len = vault::open_body(&mut f, &mut w, &fk).map_err(|e| e.to_string())?;
    w.commit().map_err(|e| e.to_string())?;
    println!("  unlocked with slot {i} ({}): {} ({len} bytes)", h.slots[i].describe(), dest.display());
    Ok(())
}

fn cmd_info(file: &Path) -> Result<(), String> {
    let (_, h) = open_vault(file)?;
    let (fp, why) = dongles_opt();
    if let Some(w) = &why {
        println!("  dongles unreadable: {w}");
    }
    println!("  {}: {} keyslot(s)", file.display(), h.slots.len());
    for (i, s) in h.slots.iter().enumerate() {
        let state = match s.check_dongle(fp.as_ref().map(|f| f as &dyn DongleSource)) {
            Ok(_) if s.needs_pass() => "openable with the passphrase".to_string(),
            Ok(_) => "openable with the plugged dongles".to_string(),
            Err(r) => r,
        };
        let kid = if s.needs_dongle() { format!(" kid {}", vault::hex(&s.kid)) } else { String::new() };
        println!("  slot {i}: {}{kid} -> {state}", s.describe());
    }
    Ok(())
}

/// Rewrite `file` with a new header, streaming the untouched body through.
fn rewrite_header(file: &Path, mut body: File, h: &Header) -> Result<(), String> {
    let mut w = AtomicWriter::create(file, true).map_err(|e| e.to_string())?;
    w.write_all(&h.to_bytes()).map_err(|e| e.to_string())?;
    std::io::copy(&mut body, &mut w).map_err(|e| e.to_string())?;
    w.commit().map_err(|e| e.to_string())
}

fn cmd_addkey(file: &Path, pin: bool, recovery: bool, dongle: bool, bind: &str) -> Result<(), String> {
    if [pin, recovery, dongle].iter().filter(|b| **b).count() != 1 {
        return Err("choose exactly one of --pin, --recovery, --dongle".into());
    }
    let (body, mut h) = open_vault(file)?;
    let (fp, why) = dongles_opt();
    if let Some(w) = &why {
        println!("  dongles unreadable: {w}");
    }
    let (opened, fk) = open_any(&h, fp.as_ref())?;
    println!("  opened with slot {opened}");
    let pass;
    let d;
    let spec = if recovery {
        pass = prompt_new("recovery passphrase (no dongles)")?;
        SlotSpec::pass(&pass)
    } else {
        let fp = fp.as_ref().ok_or("no dongles readable, cannot add a dongle keyslot")?;
        d = dongle_for(fp, bind, pin)?;
        if pin {
            pass = prompt_new("PIN (with dongles)")?;
            SlotSpec::dongle_pass(&d, &pass)
        } else {
            SlotSpec::dongle(&d)
        }
    };
    let i = h.add_slot(&fk, &spec, &mut vault::os_rng).map_err(|e| e.to_string())?;
    rewrite_header(file, body, &h)?;
    println!("  added slot {i}: {}", h.slots[i].describe());
    Ok(())
}

fn cmd_delkey(file: &Path, slot: usize) -> Result<(), String> {
    let (body, mut h) = open_vault(file)?;
    let gone = h.slots.get(slot).map(|s| s.describe()).ok_or("no such keyslot")?;
    h.remove_slot(slot).map_err(|e| e.to_string())?;
    rewrite_header(file, body, &h)?;
    println!("  removed slot {slot} ({gone}); {} left", h.slots.len());
    Ok(())
}

pub fn run() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Id => {
            let fp = read_dongles().map_err(|e| e.to_string())?;
            println!("  {}", fp.summary());
            for s in &fp.slots {
                println!(
                    "  slot {} {} {} '{}'{}",
                    s.slot,
                    s.wpid_hex(),
                    s.kind,
                    s.name,
                    if s.record.is_some() { " +record" } else { "" }
                );
            }
            if fp.ti_present {
                println!("  TI serial {}  D4 {}", vault::hex(&fp.receiver_serial), if fp.d4_open { "open" } else { "closed" });
            }
            if fp.nano_present {
                println!("  Nano serial {}", vault::hex(&fp.nano_serial));
            }
            println!("  kid {} (all plugged receivers, {})", vault::hex(&fp.kid()), vault::bind_label(fp.occupied()));
            Ok(())
        }
        Cmd::Lock { file, out, pin, recovery, bind, force } => cmd_lock(&file, out, pin, recovery, &bind, force),
        Cmd::Unlock { file, out, force } => cmd_unlock(&file, out, force),
        Cmd::Info { file } => cmd_info(&file),
        Cmd::Addkey { file, pin, recovery, dongle, bind } => cmd_addkey(&file, pin, recovery, dongle, &bind),
        Cmd::Delkey { file, slot } => cmd_delkey(&file, slot),
        Cmd::Gui { file } => {
            crate::gui::run(file);
            Ok(())
        }
    }
}
