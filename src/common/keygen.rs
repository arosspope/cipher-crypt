//! Contains functions used to generate scrambled alphabets from a key.
//!

use std::ascii::AsciiExt;
use super::alphabet;

/// Generates a scrambled alphabet using a key. Repeated letters in the key are ignored.
/// e.g. A key of `alphabet` will produce the result `alphbetcdfgijkmnoqrsuvwxyz`.
///
/// Will return Err if a non-alphabetic symbol is present in the key.
pub fn keyed_alphabet(key: &str, make_uppercase: bool) -> Result<String, &'static str> {

    // A String to store our new keyed alphabet.
    let mut keyed_alphabet = String::new();

    // Loop over the key and add each unique letter to the keyed alphabet.
    for c in key.chars() {
        match alphabet::find_position(c) {
            Some(pos) => {
                // Add the letter to the keyed alphabet if it is not already present. 
                if keyed_alphabet.chars().position(|a| a.eq_ignore_ascii_case(&c)).is_none() {
                    // pos is obtained from alphabet::find_position() therefore this unwrap is safe.
                    keyed_alphabet.push(alphabet::get_letter(pos, make_uppercase).unwrap());
                }
            },
            None => {
                // Keys can only contain characters in the known alphabet.
                return Err("Invalid key. Key cannot contain non-alphabetic symbols.");
            }
        }
    }

    // Add remaining letters to the end of the keyed alphabet.
    for index in 0..26 {
        let chr = alphabet::get_letter(index, false).unwrap();
        if keyed_alphabet.chars().position(|a| a.eq_ignore_ascii_case(&chr)).is_none() {
            // index is less than 26 therefore this unwrap is safe.
            keyed_alphabet.push(alphabet::get_letter(index, make_uppercase).unwrap());
        }
    }

    Ok(keyed_alphabet)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_alphabet() {
        let keyed_alphabet = keyed_alphabet("test", false).unwrap();
        assert_eq!(keyed_alphabet, "tesabcdfghijklmnopqruvwxyz");
    }

    #[test]
    fn generate_alphabet_mixed_key() {
        let keyed_alphabet = keyed_alphabet("ALphaBEt", false).unwrap();
        assert_eq!(keyed_alphabet, "alphbetcdfgijkmnoqrsuvwxyz");
    }

    #[test]
    fn generate_uppercase_alphabet() {
        let keyed_alphabet = keyed_alphabet("OranGE", true).unwrap();
        assert_eq!(keyed_alphabet, "ORANGEBCDFHIJKLMPQSTUVWXYZ");
    }

    #[test]
    fn generate_alphabet_bad_key() {
        assert!(keyed_alphabet("bad key", false).is_err());
    }

    #[test]
    fn generate_alphabet_no_key() {
        let keyed_alphabet = keyed_alphabet("", false).unwrap();
        assert_eq!(keyed_alphabet, "abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn generate_alphabet_long_key() {
        let keyed_alphabet = keyed_alphabet("nnhhyqzabguuxwdrvvctspefmjoklii", true).unwrap();
        assert_eq!(keyed_alphabet, "NHYQZABGUXWDRVCTSPEFMJOKLI");
    }
}
