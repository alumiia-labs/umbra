//! The hex form of a key or a seed in a file of an operator.
//!
//! One reader serves each binary, thus each of them refuses the same texts.

use alloc::{string::String, vec::Vec};

/// The value of one hex character. `from_str_radix` takes a sign, thus it
/// reads no character here: `+f` is no byte.
const fn nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character.saturating_sub(b'0')),
        b'a'..=b'f' => Some(character.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(character.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Writes the bytes of `text` to `out`. The text holds two hex characters
/// for each byte of `out`, and no other character. The bytes go into `out`
/// alone, thus a secret leaves no copy on the way.
pub fn read_into(text: &str, out: &mut [u8]) -> Option<()> {
    let characters = text.as_bytes();
    if characters.len() != out.len().checked_mul(2)? {
        return None;
    }

    let (pairs, _) = characters.as_chunks::<2>();
    for (&[high, low], byte) in pairs.iter().zip(out.iter_mut()) {
        *byte = (nibble(high)? << 4) | nibble(low)?;
    }

    Some(())
}

/// The `N` bytes of `2 * N` hex characters.
pub fn read_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    read_into(text, &mut out)?;

    Some(out)
}

/// The bytes of a hex text of an even length.
pub fn read_vec(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }

    let mut out = alloc::vec![0u8; text.len() / 2];
    read_into(text, &mut out)?;

    Some(out)
}

/// The lowercase hex form of `bytes`.
pub fn write(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            // A nibble is below 16, thus it has a digit.
            text.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }

    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_text_reads_back_to_its_bytes() {
        let bytes = [0x00, 0x0f, 0xa5, 0xff];

        assert_eq!(write(&bytes), "000fa5ff");
        assert_eq!(read_array::<4>("000fa5ff"), Some(bytes));
        assert_eq!(read_array::<4>("000FA5FF"), Some(bytes));
        assert_eq!(read_vec("000fa5ff"), Some(bytes.to_vec()));
        assert_eq!(read_vec(""), Some(Vec::new()));
    }

    #[test]
    fn a_text_of_another_length_is_no_value() {
        assert_eq!(read_array::<4>("000fa5"), None);
        assert_eq!(read_array::<4>("000fa5ff00"), None);
        assert_eq!(read_vec("000"), None);
    }

    #[test]
    fn a_text_with_a_sign_or_a_space_is_no_value() {
        assert_eq!(read_array::<2>("+f0f"), None);
        assert_eq!(read_array::<2>("-10f"), None);
        assert_eq!(read_array::<2>(" f0f"), None);
        assert_eq!(read_vec("0g"), None);
        // A character of more than one byte can make an even length.
        assert_eq!(read_vec("é"), None);
    }
}
