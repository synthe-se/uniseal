//! SDL2 vault window.
//!
//! Two cards (Receiver, Vault) over a log. Everything is laid out in
//! logical pixels and scaled at draw time, so text stays crisp on HiDPI.
//! HID and Argon2 work run in a worker thread over mpsc; file dialogs
//! (rfd) run on the UI thread. Drop a file on the window to select it;
//! a `.vault` shows its keyslots and the primary action becomes Unlock.
//! `UNISEAL_SMOKE=1` auto-quits after a few seconds (headless CI check);
//! `UNISEAL_PRIVATE=1` masks serials, key ids and device names, for
//! screenshots.

use sdl2::event::Event;
use sdl2::keyboard::{Keycode, Mod};
use sdl2::mouse::MouseButton;
use sdl2::pixels::Color;
use sdl2::rect::{Point, Rect};
use sdl2::render::{Canvas, TextureCreator};
use sdl2::rwops::RWops;
use sdl2::ttf::{Font, Sdl2TtfContext};
use sdl2::video::{Window, WindowContext};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, TryRecvError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use crate::fingerprint::{self, Fingerprint};
use crate::fsio::{self, AtomicWriter, HashReader, HashSink};
use crate::vault::{self, Dongle, DongleSource, Header, Secret, SlotSpec};

// Palette: deep slate, hairline borders. The green accent is reserved for
// the primary action and the "ready" dot; everything else stays neutral.
const BG: Color = Color::RGB(13, 15, 20);
const CARD: Color = Color::RGB(22, 25, 33);
const PANEL: Color = Color::RGB(30, 35, 46);
const LINE: Color = Color::RGB(44, 50, 64);
const TXT: Color = Color::RGB(226, 230, 238);
const DIM: Color = Color::RGB(141, 150, 168);
const FAINT: Color = Color::RGB(90, 97, 114);
const ACC: Color = Color::RGB(74, 222, 128);
const ACC_INK: Color = Color::RGB(8, 40, 20);
const FOCUS: Color = Color::RGB(120, 130, 152);
const WARN: Color = Color::RGB(250, 204, 21);
const ERR: Color = Color::RGB(248, 113, 113);
const BTN: Color = Color::RGB(34, 39, 52);
const BTN_HOV: Color = Color::RGB(46, 53, 70);

// Bundled fonts (SIL OFL, see assets/fonts/OFL-*.txt): Cal Sans for the
// wordmark, titles and buttons, Fira Code for running text.
const FONT_CAL: &[u8] = include_bytes!("../assets/fonts/CalSans-Regular.ttf");
const FONT_FIRA: &[u8] = include_bytes!("../assets/fonts/FiraCode-Regular.ttf");

const W: u32 = 900;
const H: u32 = 644;
#[cfg(target_os = "macos")]
const PASTE: &str = "Cmd+V";
#[cfg(not(target_os = "macos"))]
const PASTE: &str = "Ctrl+V";

fn r(x: i32, y: i32, w: u32, h: u32) -> Rect {
    Rect::new(x, y, w, h)
}
fn receiver_card() -> Rect {
    r(24, 68, 420, 320)
}
fn vault_card() -> Rect {
    r(462, 68, 414, 320)
}
fn log_box() -> Rect {
    r(24, 404, 852, 224)
}
fn drop_zone() -> Rect {
    r(478, 104, 382, 56)
}
fn browse_btn() -> Rect {
    r(766, 115, 82, 34)
}
fn segment_bar() -> Rect {
    r(478, 176, 382, 30)
}
fn pass_field() -> Rect {
    r(478, 290, 326, 34)
}
fn eye_btn() -> Rect {
    r(812, 290, 48, 34)
}
fn primary_btn() -> Rect {
    r(478, 338, 382, 34)
}
fn refresh_btn() -> Rect {
    r(40, 338, 110, 34)
}

// ---------------------------------------------------------------- drawing

#[derive(Clone, Copy)]
enum F {
    Ui = 0,
    Bold = 1,
    Big = 2,
    Mono = 3,
    Logo = 4,
}


struct Ui<'t> {
    canvas: Canvas<Window>,
    tc: TextureCreator<WindowContext>,
    fonts: [Font<'t, 'static>; 5],
    scale: f32,
}

impl Ui<'_> {
    fn px(&self, v: i32) -> i32 {
        (v as f32 * self.scale).round() as i32
    }
    fn sr(&self, rect: Rect) -> Rect {
        Rect::new(self.px(rect.x()), self.px(rect.y()), self.px(rect.width() as i32) as u32, self.px(rect.height() as i32) as u32)
    }
    fn fill(&mut self, rect: Rect, c: Color) {
        let s = self.sr(rect);
        self.canvas.set_draw_color(c);
        let _ = self.canvas.fill_rect(s);
    }
    fn frame(&mut self, rect: Rect, c: Color) {
        let s = self.sr(rect);
        self.canvas.set_draw_color(c);
        let _ = self.canvas.draw_rect(s);
        if self.scale > 1.5 && s.width() > 2 && s.height() > 2 {
            let _ = self.canvas.draw_rect(Rect::new(s.x() + 1, s.y() + 1, s.width() - 2, s.height() - 2));
        }
    }
    fn dashed(&mut self, rect: Rect, c: Color) {
        let (dash, gap) = (6i32, 4i32);
        let (x0, y0, x1, y1) = (rect.x(), rect.y(), rect.x() + rect.width() as i32, rect.y() + rect.height() as i32);
        let mut x = x0;
        while x < x1 {
            let w = dash.min(x1 - x) as u32;
            self.fill(r(x, y0, w, 1), c);
            self.fill(r(x, y1 - 1, w, 1), c);
            x += dash + gap;
        }
        let mut y = y0;
        while y < y1 {
            let h = dash.min(y1 - y) as u32;
            self.fill(r(x0, y, 1, h), c);
            self.fill(r(x1 - 1, y, 1, h), c);
            y += dash + gap;
        }
    }
    fn measure(&self, f: F, s: &str) -> (i32, i32) {
        match self.fonts[f as usize].size_of(s) {
            Ok((w, h)) => ((w as f32 / self.scale).round() as i32, (h as f32 / self.scale).round() as i32),
            Err(_) => (0, 0),
        }
    }
    fn text(&mut self, f: F, s: &str, c: Color, x: i32, y: i32) -> i32 {
        if s.is_empty() {
            return 0;
        }
        let Ok(surf) = self.fonts[f as usize].render(s).blended(c) else { return 0 };
        let Ok(t) = self.tc.create_texture_from_surface(&surf) else { return 0 };
        let q = t.query();
        let dst = Rect::new(self.px(x), self.px(y), q.width, q.height);
        let _ = self.canvas.copy(&t, None, dst);
        (q.width as f32 / self.scale).round() as i32
    }
    /// Draw `s` truncated with an ellipsis so it fits in `max_w` logical px.
    fn text_clip(&mut self, f: F, s: &str, c: Color, x: i32, y: i32, max_w: i32) -> i32 {
        if self.measure(f, s).0 <= max_w {
            return self.text(f, s, c, x, y);
        }
        let chars: Vec<char> = s.chars().collect();
        let mut n = chars.len();
        while n > 1 {
            n -= 1;
            let t: String = chars[..n].iter().collect::<String>() + "…";
            if self.measure(f, &t).0 <= max_w {
                return self.text(f, &t, c, x, y);
            }
        }
        0
    }
    fn text_right(&mut self, f: F, s: &str, c: Color, right: i32, y: i32) -> i32 {
        let (w, _) = self.measure(f, s);
        self.text(f, s, c, right - w, y)
    }
    fn text_center(&mut self, f: F, s: &str, c: Color, rect: Rect) {
        let (w, h) = self.measure(f, s);
        self.text(f, s, c, rect.x() + (rect.width() as i32 - w) / 2, rect.y() + (rect.height() as i32 - h) / 2);
    }
    fn card(&mut self, rect: Rect, title: &str) {
        self.fill(rect, CARD);
        self.frame(rect, LINE);
        self.text(F::Bold, title, FAINT, rect.x() + 16, rect.y() + 12);
    }
    fn button(&mut self, rect: Rect, label: &str, primary: bool, hover: bool, enabled: bool) {
        let (bg, ink, edge) = match (primary, enabled, hover) {
            (true, true, true) => (Color::RGB(110, 236, 152), ACC_INK, ACC),
            (true, true, false) => (ACC, ACC_INK, ACC),
            (true, false, _) => (PANEL, FAINT, LINE),
            (false, true, true) => (BTN_HOV, TXT, FOCUS),
            (false, true, false) => (BTN, TXT, LINE),
            (false, false, _) => (CARD, FAINT, LINE),
        };
        self.fill(rect, bg);
        self.frame(rect, edge);
        self.text_center(F::Bold, label, ink, rect);
    }
    fn dot(&mut self, x: i32, y: i32, c: Color) {
        self.fill(r(x, y, 6, 6), c);
    }
    /// Wordmark: plain Cal Sans, white. Returns its width.
    fn logo(&mut self, x: i32, y: i32) -> i32 {
        self.text(F::Logo, "Uniseal", TXT, x, y)
    }
    /// 5x5 mirrored identicon from the public key id (visual dongle identity).
    fn identicon(&mut self, kid: &[u8; 8], x: i32, y: i32, cell: i32) {
        use sha2::{Digest, Sha256};
        let h = Sha256::digest(kid);
        let shade = 150 + h[0] % 60;
        let col = Color::RGB(shade, shade + 4, shade + 10);
        self.fill(r(x - 4, y - 4, (cell * 5 + 8) as u32, (cell * 5 + 8) as u32), PANEL);
        for row in 0..5 {
            for c in 0..3 {
                if h[3 + ((row * 3 + c) % 29) as usize] % 2 == 0 {
                    self.fill(r(x + c * cell, y + row * cell, cell as u32, cell as u32), col);
                    self.fill(r(x + (4 - c) * cell, y + row * cell, cell as u32, cell as u32), col);
                }
            }
        }
    }
}

fn embedded<'t>(ttf: &'t Sdl2TtfContext, bytes: &'static [u8], pt: f32, scale: f32) -> Font<'t, 'static> {
    let rw = RWops::from_bytes(bytes).expect("font rwops");
    ttf.load_font_from_rwops(rw, (pt * scale).round() as u16).expect("bundled font")
}

fn load_fonts(ttf: &Sdl2TtfContext, scale: f32) -> [Font<'_, 'static>; 5] {
    [
        embedded(ttf, FONT_FIRA, 12.0, scale),
        embedded(ttf, FONT_CAL, 13.5, scale),
        embedded(ttf, FONT_CAL, 19.0, scale),
        embedded(ttf, FONT_FIRA, 12.0, scale),
        embedded(ttf, FONT_CAL, 24.0, scale),
    ]
}

// ---------------------------------------------------------------- state

fn stamp() -> String {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (t / 3600) % 24, (t / 60) % 60, t % 60)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Level {
    Info,
    Ok,
    Warn,
    Err,
}

impl Level {
    fn color(self) -> Color {
        match self {
            Level::Info => FAINT,
            Level::Ok => DIM,
            Level::Warn => WARN,
            Level::Err => ERR,
        }
    }
}

#[derive(Clone, Default)]
struct Status {
    ok: bool,
    detail: String,
    name: String,
    line: String,
    serial: String,
    nano: Option<String>,
    /// (label, has pairing record, receiver slot number)
    devices: Vec<(String, bool, u8)>,
    fp: Option<Fingerprint>,
    strong: bool,
    nkeys: u8,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Dongle,
    DonglePin,
    DongleRecovery,
}

impl Mode {
    const ALL: [Mode; 3] = [Mode::Dongle, Mode::DonglePin, Mode::DongleRecovery];
    fn label(self) -> &'static str {
        match self {
            Mode::Dongle => "Dongle",
            Mode::DonglePin => "Dongle + PIN",
            Mode::DongleRecovery => "+ Recovery",
        }
    }
    fn hint(self) -> &'static str {
        match self {
            Mode::Dongle => "Anyone holding the dongles opens it.",
            Mode::DonglePin => "Dongles and PIN both required (Argon2id).",
            Mode::DongleRecovery => "Dongle slot + passphrase slot without dongles.",
        }
    }
    fn needs_pass(self) -> bool {
        self != Mode::Dongle
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    File,
    Pass,
}

/// What `inspect` learned about the selected file.
#[derive(Clone)]
struct SlotView {
    desc: String,
    state: String,
    level: Level,
}

enum Job {
    Refresh,
    Inspect { path: PathBuf, fp: Option<Fingerprint> },
    Lock { path: PathBuf, dongle: Dongle, mode: Mode, pass: Secret },
    Unlock { path: PathBuf, fp: Option<Fingerprint>, pass: Secret },
}

enum Done {
    Status(Box<Status>),
    Inspect(Option<Vec<SlotView>>),
    Line(String, Level),
}

// ---------------------------------------------------------------- worker

fn refresh(api: &hidapi::HidApi) -> Status {
    let mut st = Status::default();
    match fingerprint::collect(api) {
        Ok(fp) => {
            st.ok = true;
            st.nkeys = fp.nkeys();
            st.strong = st.nkeys > 0;
            st.name = match (fp.ti_present, fp.nano_present) {
                (true, true) => "TI C52B + Nano C52F".into(),
                (true, false) => "TI C52B".into(),
                _ => "Nano C52F".into(),
            };
            if fp.ti_present {
                st.line = format!(
                    "{} · D4 {} · {} record{}",
                    fp.firmware,
                    if fp.d4_open { "open" } else { "closed" },
                    st.nkeys,
                    if st.nkeys == 1 { "" } else { "s" }
                );
                st.serial = format!("serial {}", vault::hex(&fp.receiver_serial));
            } else {
                st.line = "Nano only: serial, no pairing record".into();
                st.serial = format!("serial {}", vault::hex(&fp.nano_serial));
            }
            st.nano = if fp.nano_present { Some(format!("Nano C52F {}", vault::hex(&fp.nano_serial))) } else { None };
            for s in &fp.slots {
                let name = if s.name.is_empty() { format!("wpid {}", s.wpid_hex()) } else { s.name.clone() };
                st.devices.push((format!("{name} · {}", s.kind), s.record.is_some(), s.slot));
            }
            st.fp = Some(fp);
            st.detail = "receiver ready".into();
        }
        Err(e) => st.detail = e.to_string(),
    }
    st
}

/// Parse only the header of a vault: keyslots and whether each can open now.
fn inspect(path: &Path, fp: Option<&Fingerprint>) -> Option<Vec<SlotView>> {
    let mut f = File::open(path).ok()?;
    let h = Header::read(&mut f).ok()?;
    let src = fp.map(|f| f as &dyn DongleSource);
    Some(
        h.slots
            .iter()
            .map(|s| {
                let desc = s.describe();
                match s.check_dongle(src) {
                    Ok(_) if s.needs_pass() => SlotView { desc, state: "needs passphrase".into(), level: Level::Warn },
                    Ok(_) => SlotView { desc, state: "opens now".into(), level: Level::Ok },
                    Err(why) if why.contains("none readable") => SlotView { desc, state: "no dongles".into(), level: Level::Err },
                    Err(why) if why.contains("missing") => SlotView { desc, state: "device missing".into(), level: Level::Err },
                    Err(why) if why.contains("needs dongle") => SlotView { desc, state: "other dongles".into(), level: Level::Err },
                    Err(_) => SlotView { desc, state: "kid mismatch".into(), level: Level::Err },
                }
            })
            .collect(),
    )
}

fn do_lock(path: &Path, dongle: &Dongle, mode: Mode, pass: &Secret) -> Result<String, String> {
    let specs = match mode {
        Mode::Dongle => vec![SlotSpec::dongle(dongle)],
        Mode::DonglePin => vec![SlotSpec::dongle_pass(dongle, pass)],
        Mode::DongleRecovery => vec![SlotSpec::dongle(dongle), SlotSpec::pass(pass)],
    };
    let dest = fsio::vault_path(path);
    let mut src = HashReader::new(File::open(path).map_err(|e| format!("read: {e}"))?);
    let mut w = AtomicWriter::create(&dest, false).map_err(|e| e.to_string())?;
    let (header, len) = vault::seal(&mut src, &mut w, &specs, &mut vault::os_rng).map_err(|e| e.to_string())?;
    w.commit().map_err(|e| e.to_string())?;
    let digest = src.digest();
    // Self-check: every slot unwraps, the body decrypts back to the same bytes.
    let verify = || -> Result<(), String> {
        let mut f = File::open(&dest).map_err(|e| e.to_string())?;
        let check = Header::read(&mut f).map_err(|e| e.to_string())?;
        let mut keys = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            keys.push(check.open_slot(i, spec.dongle.map(|d| d.material.as_slice()), spec.pass).map_err(|e| format!("slot {i}: {e}"))?);
        }
        let mut sink = HashSink::default();
        vault::open_body(&mut f, &mut sink, &keys[0]).map_err(|e| e.to_string())?;
        if sink.digest() != digest { Err("plaintext digest differs".into()) } else { Ok(()) }
    };
    if let Err(e) = verify() {
        let _ = std::fs::remove_file(&dest);
        return Err(format!("self-check failed ({e}), vault removed"));
    }
    let size = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
    Ok(format!("locked {} ({len} -> {size} B, {} keyslot{})", dest.display(), header.slots.len(), if header.slots.len() == 1 { "" } else { "s" }))
}

fn do_unlock(path: &Path, fp: Option<&Fingerprint>, pass: &Secret) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("read: {e}"))?;
    let h = Header::read(&mut f).map_err(|e| e.to_string())?;
    let src = fp.map(|f| f as &dyn DongleSource);
    let (i, fk) = h
        .unlock_any(src, &mut |_, _| if pass.is_empty() { None } else { Some(pass.clone()) })
        .map_err(|e| e.to_string().replace('\n', " |"))?;
    let dest = fsio::open_path(path);
    let mut w = AtomicWriter::create(&dest, false).map_err(|e| e.to_string())?;
    let len = vault::open_body(&mut f, &mut w, &fk).map_err(|e| e.to_string())?;
    w.commit().map_err(|e| e.to_string())?;
    Ok(format!("unlocked with keyslot {i} ({}) -> {} ({len} B)", h.slots[i].describe(), dest.display()))
}

fn worker(rx: Receiver<Job>, tx: Sender<Done>) {
    let api = match hidapi::HidApi::new() {
        Ok(a) => a,
        Err(e) => {
            let _ = tx.send(Done::Line(format!("hidapi: {e}"), Level::Err));
            return;
        }
    };
    let report = |res: Result<String, String>| match res {
        Ok(s) => Done::Line(s, Level::Ok),
        Err(e) => Done::Line(e, Level::Err),
    };
    for job in rx {
        let _ = match job {
            Job::Refresh => tx.send(Done::Status(Box::new(refresh(&api)))),
            Job::Inspect { path, fp } => tx.send(Done::Inspect(inspect(&path, fp.as_ref()))),
            Job::Lock { path, dongle, mode, pass } => tx.send(report(do_lock(&path, &dongle, mode, &pass))),
            Job::Unlock { path, fp, pass } => tx.send(report(do_unlock(&path, fp.as_ref(), &pass))),
        };
    }
}

// ---------------------------------------------------------------- app

struct App {
    path: String,
    slots: Option<Vec<SlotView>>,
    pass: Zeroizing<String>,
    show_pass: bool,
    focus: Focus,
    mode: Mode,
    logs: Vec<(String, Level)>,
    status: Status,
    busy: bool,
    hover: Point,
    path_dirty: bool,
    /// Receiver slots included in the next Lock (toggled by clicking chips).
    bind: u8,
    chips: Vec<(Rect, u8)>,
}

impl App {
    fn log(&mut self, s: impl Into<String>, level: Level) {
        self.logs.push((format!("{}  {}", stamp(), s.into()), level));
        while self.logs.len() > 10 {
            self.logs.remove(0);
        }
    }
    fn is_vault(&self) -> bool {
        self.slots.is_some()
    }
    fn pass_needed(&self) -> bool {
        match &self.slots {
            Some(slots) => slots.iter().any(|s| s.level == Level::Warn),
            None => self.mode.needs_pass(),
        }
    }
    fn set_path(&mut self, p: String) {
        if p != self.path {
            self.path = p;
            self.slots = None;
            self.path_dirty = true;
        }
    }
    fn primary_label(&self) -> (String, bool) {
        if self.path.is_empty() {
            return ("Select a file".into(), false);
        }
        let p = Path::new(&self.path);
        if self.is_vault() {
            let dest = fsio::open_path(p);
            (format!("Unlock · {}", dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()), !self.busy)
        } else {
            let dest = fsio::vault_path(p);
            (format!("Lock · {}", dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()), !self.busy)
        }
    }
    fn hovering(&self, rect: Rect) -> bool {
        rect.contains_point(self.hover)
    }
}

fn paste_text(video: &sdl2::VideoSubsystem) -> String {
    video.clipboard().clipboard_text().unwrap_or_default().lines().next().unwrap_or_default().to_string()
}

pub fn run(preselected: Option<PathBuf>) {
    let smoke = std::env::var("UNISEAL_SMOKE").is_ok();
    let private = std::env::var("UNISEAL_PRIVATE").is_ok();
    let sdl = sdl2::init().expect("SDL2");
    let video = sdl.video().expect("video");
    let ttf = sdl2::ttf::init().expect("ttf");
    let window = video.window("Uniseal", W, H).position_centered().allow_highdpi().build().expect("window");
    let (win_w, _) = window.size();
    let canvas = window.into_canvas().present_vsync().build().expect("canvas");
    let (out_w, _) = canvas.output_size().unwrap_or((win_w, H));
    let scale = (out_w as f32 / win_w as f32).max(1.0);
    let tc = canvas.texture_creator();
    let mut ui = Ui { canvas, tc, fonts: load_fonts(&ttf, scale), scale };
    video.text_input().start();

    let (tx, worker_rx): (Sender<Job>, Receiver<Job>) = channel();
    let (worker_tx, rx): (Sender<Done>, Receiver<Done>) = channel();
    std::thread::spawn(move || worker(worker_rx, worker_tx));

    let mut app = App {
        path: String::new(),
        slots: None,
        pass: Zeroizing::new(String::new()),
        show_pass: false,
        focus: Focus::File,
        mode: Mode::Dongle,
        logs: Vec::new(),
        status: Status::default(),
        busy: true,
        hover: Point::new(-1, -1),
        path_dirty: false,
        bind: 0,
        chips: Vec::new(),
    };
    app.log("reading receivers…", Level::Info);
    if let Some(p) = preselected {
        app.set_path(p.display().to_string());
    }
    let _ = tx.send(Job::Refresh);
    let started = Instant::now();
    let pass_bytes = |p: &Zeroizing<String>| -> Secret { Zeroizing::new(p.as_bytes().to_vec()) };

    let mut events = sdl.event_pump().expect("events");
    'ui: loop {
        if smoke && started.elapsed() > Duration::from_secs(25) {
            break 'ui;
        }
        let mut fire_primary = false;
        for ev in events.poll_iter() {
            match ev {
                Event::Quit { .. } | Event::KeyDown { keycode: Some(Keycode::Escape), .. } => break 'ui,
                Event::MouseMotion { x, y, .. } => app.hover = Point::new(x, y),
                Event::DropFile { filename, .. } => app.set_path(filename),
                Event::MouseButtonDown { x, y, mouse_btn: MouseButton::Left, .. } => {
                    let pt = Point::new(x, y);
                    if drop_zone().contains_point(pt) && !browse_btn().contains_point(pt) {
                        app.focus = Focus::File;
                    } else if pass_field().contains_point(pt) {
                        app.focus = Focus::Pass;
                    }
                    if eye_btn().contains_point(pt) && app.pass_needed() {
                        app.show_pass = !app.show_pass;
                    }
                    if app.busy {
                        continue;
                    }
                    if !app.is_vault() && segment_bar().contains_point(pt) {
                        let seg = ((x - segment_bar().x()) * 3 / segment_bar().width() as i32).clamp(0, 2);
                        app.mode = Mode::ALL[seg as usize];
                    }
                    if browse_btn().contains_point(pt)
                        && let Some(p) = rfd::FileDialog::new().pick_file()
                    {
                        app.set_path(p.display().to_string());
                    }
                    if primary_btn().contains_point(pt) {
                        fire_primary = true;
                    }
                    if refresh_btn().contains_point(pt) {
                        app.busy = tx.send(Job::Refresh).is_ok();
                    }
                    for (rect, slot) in app.chips.clone() {
                        if rect.contains_point(pt) {
                            app.bind ^= 1 << (slot - 1);
                        }
                    }
                }
                Event::TextInput { text, .. } => match app.focus {
                    Focus::File => {
                        let p = app.path.clone() + &text;
                        app.set_path(p);
                    }
                    Focus::Pass => app.pass.push_str(&text),
                },
                Event::KeyDown { keycode: Some(k), keymod, .. } => {
                    let cmd = keymod.intersects(Mod::LGUIMOD | Mod::RGUIMOD | Mod::LCTRLMOD | Mod::RCTRLMOD);
                    match k {
                        Keycode::Backspace => match app.focus {
                            Focus::File => {
                                let mut p = app.path.clone();
                                if cmd { p.clear() } else { p.pop(); }
                                app.set_path(p);
                            }
                            Focus::Pass => {
                                if cmd { app.pass.clear() } else { app.pass.pop(); }
                            }
                        },
                        Keycode::Tab => {
                            app.focus = if app.focus == Focus::File && app.pass_needed() { Focus::Pass } else { Focus::File };
                        }
                        Keycode::Return | Keycode::KpEnter => fire_primary = true,
                        Keycode::V if cmd => {
                            let t = paste_text(&video);
                            match app.focus {
                                Focus::File => app.set_path(t),
                                Focus::Pass => app.pass.push_str(&t),
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if fire_primary && !app.busy && !app.path.is_empty() {
            let path = PathBuf::from(&app.path);
            if app.is_vault() {
                app.busy = tx.send(Job::Unlock { path, fp: app.status.fp.clone(), pass: pass_bytes(&app.pass) }).is_ok();
            } else if let Some(fp) = app.status.fp.clone() {
                if app.mode.needs_pass() && app.pass.is_empty() {
                    app.log(format!("{}: type a passphrase first", app.mode.label()), Level::Err);
                    app.focus = Focus::Pass;
                } else {
                    match fp.dongle(Some(app.bind)) {
                        Ok(dongle) => {
                            if dongle.nkeys == 0 && app.mode == Mode::Dongle {
                                app.log("warning: no pairing record in this binding, serials only; consider a PIN", Level::Warn);
                            }
                            app.busy = tx.send(Job::Lock { path, dongle, mode: app.mode, pass: pass_bytes(&app.pass) }).is_ok();
                        }
                        Err(e) => app.log(e, Level::Err),
                    }
                }
            } else {
                app.log("no dongle fingerprint: plug a receiver and Refresh", Level::Err);
            }
        }
        if app.path_dirty {
            app.path_dirty = false;
            let _ = tx.send(Job::Inspect { path: PathBuf::from(&app.path), fp: app.status.fp.clone() });
        }
        loop {
            match rx.try_recv() {
                Ok(Done::Status(st)) => {
                    let ok = st.ok;
                    let detail = st.detail.clone();
                    app.bind = st.fp.as_ref().map(|f| f.occupied()).unwrap_or(0);
                    app.status = *st;
                    app.busy = false;
                    app.log(detail, if ok { Level::Ok } else { Level::Err });
                    app.path_dirty = !app.path.is_empty();
                }
                Ok(Done::Inspect(slots)) => app.slots = slots,
                Ok(Done::Line(s, level)) => {
                    if level == Level::Ok {
                        app.pass.clear();
                    }
                    app.log(s, level);
                    app.busy = false;
                    app.path_dirty = !app.path.is_empty();
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break 'ui,
            }
        }

        // ---- render ----
        ui.fill(r(0, 0, W, H), BG);
        // Header.
        let w = ui.logo(24, 12);
        ui.text(F::Ui, "possession is access", FAINT, 24 + w + 16, 22);
        let (pill, color) = if app.busy {
            let ph = (started.elapsed().as_millis() / 300).is_multiple_of(2);
            ("working…", if ph { DIM } else { FAINT })
        } else if app.status.ok {
            ("receiver ready", ACC)
        } else {
            ("no receiver", DIM)
        };
        let (pw, _) = ui.measure(F::Ui, pill);
        let pr = r(876 - pw - 26, 16, (pw + 26) as u32, 26);
        ui.fill(pr, CARD);
        ui.frame(pr, LINE);
        ui.dot(pr.x() + 9, pr.y() + 10, color);
        ui.text(F::Ui, pill, DIM, pr.x() + 20, pr.y() + 5);
        ui.fill(r(24, 56, 852, 1), LINE);

        // Receiver card.
        let rc = receiver_card();
        ui.card(rc, "RECEIVER");
        let st = app.status.clone();
        if let Some(fp) = &st.fp {
            let kid = if private { [0x55; 8] } else { fp.kid() };
            let (grade, gc) = if st.strong { (format!("records ×{}", st.nkeys), DIM) } else { ("serials only".to_string(), WARN) };
            let (gw, _) = ui.measure(F::Ui, &grade);
            let gr = r(rc.x() + rc.width() as i32 - gw - 32, rc.y() + 10, (gw + 16) as u32, 22);
            ui.fill(gr, PANEL);
            ui.frame(gr, LINE);
            ui.text(F::Ui, &grade, gc, gr.x() + 8, gr.y() + 3);
            ui.identicon(&kid, 44, 114, 12);
            ui.text(F::Big, &st.name, TXT, 120, 104);
            ui.text_clip(F::Ui, &st.line, DIM, 120, 132, 300);
            let kid_line = if private {
                "serial ········ · kid ················".to_string()
            } else {
                format!("{} · kid {}", st.serial, vault::hex(&kid))
            };
            ui.text_clip(F::Mono, &kid_line, FAINT, 120, 152, 310);
            match &st.nano {
                Some(_) if private => ui.text(F::Ui, "Nano C52F ········", DIM, 120, 172),
                Some(n) => ui.text_clip(F::Ui, n, DIM, 120, 172, 300),
                None => ui.text(F::Ui, "Nano absent", FAINT, 120, 172),
            };
        } else {
            ui.text(F::Big, "No receiver", TXT, 40, 104);
            ui.text_clip(F::Ui, &st.detail, DIM, 40, 132, 380);
            ui.text_clip(F::Ui, "Passphrase keyslots still open with Unlock.", FAINT, 40, 152, 380);
        }
        ui.fill(r(40, 198, 388, 1), LINE);
        ui.text(F::Bold, "PAIRED DEVICES", FAINT, 40, 208);
        if st.devices.is_empty() {
            ui.text(F::Ui, "none readable", FAINT, 40, 232);
        } else {
            app.chips.clear();
            let (mut cx, mut cy) = (40, 230);
            for (i, (label, rec, slot)) in st.devices.iter().enumerate() {
                let label = if private { format!("device {slot} · {}", label.rsplit(" · ").next().unwrap_or("")) } else { label.clone() };
                let tag = if *rec { format!("{label} · rec") } else { label };
                let (tw, _) = ui.measure(F::Ui, &tag);
                let tw = tw.min(200);
                if cx + tw + 26 > 428 {
                    cx = 40;
                    cy += 32;
                }
                if cy > 262 {
                    ui.text(F::Ui, &format!("+{} more", st.devices.len() - i), FAINT, cx, cy - 32 + 5);
                    break;
                }
                let on = app.bind & (1 << (slot - 1)) != 0;
                let chip = r(cx, cy, (tw + 26) as u32, 24);
                ui.fill(chip, if on { PANEL } else { CARD });
                ui.frame(chip, if app.hovering(chip) { FOCUS } else { LINE });
                if on {
                    ui.dot(cx + 8, cy + 9, TXT);
                } else {
                    ui.frame(r(cx + 8, cy + 9, 6, 6), FAINT);
                }
                ui.text_clip(F::Ui, &tag, if on { TXT } else { FAINT }, cx + 18, cy + 4, tw);
                app.chips.push((chip, *slot));
                cx += tw + 34;
            }
        }
        if !st.devices.is_empty() {
            ui.text(F::Ui, "click a device to bind or unbind it", FAINT, 40, 300);
        }
        ui.button(refresh_btn(), "Refresh", false, app.hovering(refresh_btn()), !app.busy);

        // Vault card.
        let vc = vault_card();
        ui.card(vc, "VAULT");
        let dz = drop_zone();
        ui.fill(dz, PANEL);
        ui.dashed(dz, if app.focus == Focus::File { FOCUS } else { LINE });
        if app.path.is_empty() {
            ui.text(F::Bold, "Drop a file here", TXT, dz.x() + 16, dz.y() + 10);
            ui.text(F::Ui, &format!("or Browse…, or paste a path ({PASTE})"), FAINT, dz.x() + 16, dz.y() + 32);
        } else {
            let p = Path::new(&app.path);
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| app.path.clone());
            let dir = p.parent().map(|d| d.display().to_string()).unwrap_or_default();
            let kind = if app.is_vault() { "  ·  vault" } else { "" };
            ui.text_clip(F::Bold, &format!("{name}{kind}"), TXT, dz.x() + 16, dz.y() + 10, 260);
            ui.text_clip(F::Ui, &dir, FAINT, dz.x() + 16, dz.y() + 31, 260);
        }
        ui.button(browse_btn(), "Browse…", false, app.hovering(browse_btn()), !app.busy);

        let hint;
        if let Some(slots) = &app.slots {
            ui.text(F::Bold, "KEYSLOTS", FAINT, 478, 176);
            let mut y = 196;
            for (i, s) in slots.iter().enumerate() {
                if i == 3 && slots.len() > 3 {
                    ui.text(F::Ui, &format!("+{} more", slots.len() - 3), FAINT, 478, y);
                    break;
                }
                ui.dot(478, y + 5, if s.level == Level::Ok { ACC } else { s.level.color() });
                let (sw, _) = ui.measure(F::Ui, &s.state);
                ui.text_clip(F::Ui, &s.desc, TXT, 492, y, 360 - sw);
                ui.text_right(F::Ui, &s.state, if s.level == Level::Ok { DIM } else { s.level.color() }, 860, y);
                y += 18;
            }
            hint = "Tries every keyslot; passphrase if one needs it.";
        } else {
            let sb = segment_bar();
            ui.fill(sb, PANEL);
            ui.frame(sb, LINE);
            let seg_w = sb.width() as i32 / 3;
            for (i, m) in Mode::ALL.iter().enumerate() {
                let sr = r(sb.x() + seg_w * i as i32, sb.y(), seg_w as u32, sb.height());
                let on = *m == app.mode;
                if on {
                    ui.fill(sr, BTN_HOV);
                    ui.fill(r(sr.x(), sr.y() + sr.height() as i32 - 2, sr.width(), 2), TXT);
                }
                ui.text_center(F::Bold, m.label(), if on { TXT } else { DIM }, sr);
            }
            hint = app.mode.hint();
            if let Some(fp) = &st.fp {
                let line = match fp.dongle(Some(app.bind)) {
                    Ok(d) => format!("binding: {} · {} · {} rec.", vault::dongles_label(d.dongles), vault::bind_label(d.bind), d.nkeys),
                    Err(e) => e,
                };
                ui.text_clip(F::Ui, &line, DIM, 478, 216, 382);
            }
        }
        ui.text_clip(F::Ui, hint, FAINT, 478, 258, 382);

        if app.pass_needed() {
            let pf = pass_field();
            ui.fill(pf, PANEL);
            ui.frame(pf, if app.focus == Focus::Pass { FOCUS } else { LINE });
            let label = if app.is_vault() { "passphrase / PIN" } else if app.mode == Mode::DonglePin { "PIN" } else { "recovery passphrase" };
            if app.pass.is_empty() {
                ui.text(F::Ui, label, FAINT, pf.x() + 10, pf.y() + 8);
            } else if app.show_pass {
                ui.text_clip(F::Mono, &app.pass, TXT, pf.x() + 10, pf.y() + 9, 318);
            } else {
                let masked = "•".repeat(app.pass.chars().count().min(48));
                ui.text_clip(F::Mono, &masked, TXT, pf.x() + 10, pf.y() + 9, 318);
            }
            ui.button(eye_btn(), if app.show_pass { "hide" } else { "show" }, false, app.hovering(eye_btn()), true);
        } else {
            ui.text(F::Ui, "No passphrase needed.", FAINT, 478, 300);
        }
        let (label, enabled) = app.primary_label();
        let label = if app.busy { "working…".to_string() } else { label };
        ui.button(primary_btn(), &label, true, app.hovering(primary_btn()), enabled);

        // Log.
        let lb = log_box();
        ui.card(lb, "LOG");
        ui.text_right(F::Ui, &format!("enter run · tab field · {PASTE} paste · esc quit"), FAINT, lb.x() + lb.width() as i32 - 16, lb.y() + 13);
        let mut y = lb.y() + 36;
        for (s, level) in &app.logs {
            ui.dot(lb.x() + 16, y + 5, level.color());
            ui.text_clip(F::Mono, s, if *level == Level::Info { DIM } else { TXT }, lb.x() + 30, y, lb.width() as i32 - 46);
            y += 18;
        }
        ui.canvas.present();
        std::thread::sleep(Duration::from_millis(16));
    }
}
