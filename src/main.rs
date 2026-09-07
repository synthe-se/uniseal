//! uniseal: file vault bound to Logitech Unifying receivers.
//!
//! Copyright (C) 2026 Synthe.se
//! Licensed under the GNU GPL v3 or later, see LICENSE.

mod cli;
mod fingerprint;
mod fsio;
mod gui;
mod hid;
mod vault;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
