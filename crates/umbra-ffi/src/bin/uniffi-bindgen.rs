//! The binding generator of UniFFI, at the version that the crate pins.
//! `scripts/android.sh` runs it over the host library to write the Kotlin
//! file of the app.

fn main() {
    uniffi::uniffi_bindgen_main();
}
