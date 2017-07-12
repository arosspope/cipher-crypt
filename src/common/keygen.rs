//! This module contains functions for the generation of keys.
//!
use std::collections::HashMap;
use std::ascii::AsciiExt;
use super::alphabet;

/// Generates a scrambled alphabet using a key. Repeated letters in the key are ignored.
/// e.g. A key of `alphabet` will produce the result `alphbetcdfgijkmnoqrsuvwxyz`.
///
/// Will return Err if a non-alphabetic symbol is present in the key.
pub fn keyed_alphabet(key: &str, is_uppercase: bool) -> Result<String, &'static str> {
    if !alphabet::is_alphabetic_only(&key) {
        return Err("Invalid key. Key cannot contain non-alphabetic symbols.");
    }

    //Loop through each value in the key and add to our keyed alphabet if it isn't already there
    let mut keyed_alphabet = String::new();
    for c in key.chars() {
        if keyed_alphabet.chars().find(|a| a.eq_ignore_ascii_case(&c)).is_none() {
            match is_uppercase {
                true => keyed_alphabet.push_str(&c.to_uppercase().to_string()),
                false => keyed_alphabet.push_str(&c.to_lowercase().to_string()),
            }
        }
    }

    // Add remaining letters to the end of the keyed alphabet.
    for index in 0..26 {
        let c = alphabet::get_letter(index, is_uppercase).unwrap();
        if keyed_alphabet.chars().find(|a| a.eq_ignore_ascii_case(&c)).is_none() {
            keyed_alphabet.push(c);
        }
    }

    Ok(keyed_alphabet)
}

pub fn polybius_square(key_square: &str, col_key: [char; 5], row_key: [char; 5])
    -> Result<HashMap<String, char>, &'static str> {

    if key_square.len() != 25 {
        return Err("A polybius key square must have a length of 25 (alphabet key with i/j
            combined).");
    } else if !alphabet::is_alphabetic_only(key_square) {
        return Err("A polybius key square cannot contain non-alphabetic symbols.");
    }

    //TODO: check that each element of the alphabet is present

    //Check that i and j have been combined
    if key_square.chars().into_iter().any(|c| c.eq_ignore_ascii_case(&'i')) &&
        key_square.chars().into_iter().any(|c| c.eq_ignore_ascii_case(&'j'))
    {
        return Err("The characters 'i' & 'j' are combined in the polybius square. Only one of the
            two can be included in the key squre.");
    }

    let mut square_chars = key_square.chars().into_iter();
    let mut polybius_square = HashMap::new();

    for i in 0..5 { //columns
        for j in 0..5 { //rows
            let mut key = String::from(row_key[j].to_string());
            key.push(col_key[i]);
            polybius_square.insert(key, square_chars.next().expect("Key square not big enough."));

            //TODO: check if i or j then push a new entry if so
        }
    }

    Ok(polybius_square)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polybius_hashmap_order(){
        let p = polybius_square("abcdefghiklmnopqrstuvwxyz", ['a', 'b', 'c', 'd', 'e'], ['a', 'b', 'c', 'd', 'e']).unwrap();

        assert_eq!(&'a', p.get("aa").unwrap());
        assert_eq!(&'c', p.get("ac").unwrap());
        assert_eq!(&'e', p.get("ae").unwrap());
    }

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
