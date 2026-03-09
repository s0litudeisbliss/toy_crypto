//! Toy implementation of the Caesar cipher.
//!
//! The Caesar cipher shifts each letter in the plaintext by a fixed number of
//! positions in the alphabet. Only ASCII letters (A–Z, a–z) are shifted;
//! all other characters are passed through unchanged.
//!
//! # Example
//! ```
//! use caesar::{encrypt, decrypt};
//!
//! let plaintext  = "Hello, World!";
//! let ciphertext = encrypt(plaintext, 13);   // ROT-13
//! assert_eq!(ciphertext, "Uryyb, Jbeyq!");
//! assert_eq!(decrypt(&ciphertext, 13), plaintext);
//! ```

/// Encrypts `plaintext` by shifting every ASCII letter forward by `shift`
/// positions (wrapping within the same case).
pub fn encrypt(plaintext: &str, shift: u8) -> String {
    shift_text(plaintext, shift)
}

/// Decrypts `ciphertext` produced by [`encrypt`] with the same `shift`.
pub fn decrypt(ciphertext: &str, shift: u8) -> String {
    // Decryption is encryption with the complementary shift.
    let shift = shift % 26;
    shift_text(ciphertext, 26 - shift)
}

fn shift_char(c: char, shift: u8) -> char {
    let shift = shift % 26;
    match c {
        'A'..='Z' => (b'A' + (c as u8 - b'A' + shift) % 26) as char,
        'a'..='z' => (b'a' + (c as u8 - b'a' + shift) % 26) as char,
        other => other,
    }
}

fn shift_text(text: &str, shift: u8) -> String {
    text.chars().map(|c| shift_char(c, shift)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_rot13() {
        assert_eq!(encrypt("Hello, World!", 13), "Uryyb, Jbeyq!");
    }

    #[test]
    fn decrypt_rot13() {
        assert_eq!(decrypt("Uryyb, Jbeyq!", 13), "Hello, World!");
    }

    #[test]
    fn round_trip() {
        let msg = "The quick brown fox jumps over the lazy dog.";
        for shift in 0u8..=25 {
            assert_eq!(decrypt(&encrypt(msg, shift), shift), msg);
        }
    }

    #[test]
    fn shift_zero_is_identity() {
        let msg = "No change here!";
        assert_eq!(encrypt(msg, 0), msg);
    }

    #[test]
    fn non_alpha_unchanged() {
        assert_eq!(encrypt("1 + 1 = 2", 7), "1 + 1 = 2");
    }

    #[test]
    fn shift_wraps_at_26() {
        assert_eq!(encrypt("abc", 26), "abc");
        assert_eq!(encrypt("abc", 27), encrypt("abc", 1));
    }
}
