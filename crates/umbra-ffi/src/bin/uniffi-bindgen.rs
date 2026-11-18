//! The binding generator of UniFFI, at the version that the crate pins.
//! `scripts/android.sh` runs it over the host library to write the Kotlin
//! file of the app.
#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]

fn main() {
    uniffi::uniffi_bindgen_main();
}
