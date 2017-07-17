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

/// Generate a 6x6 polybius square hashmap from an alphanumeric key.
/// For successfull generation, the following must be met:
///
/// * The `key` must have a length of 36.
/// * The `key` must contain each character of the alphanumeric alphabet `a-z`, `0-9`.
/// * The `key` must contain alphanumeric characters only.
/// * The `column_ids` and `row_ids` must contain alphabetic characters only.
///
/// # Example
/// Lets say the key was `or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z` and the ids were
/// `column_ids = ['A','B','C','D','E', 'F']` `row_ids = ['A','B','C','D','E', 'F']`. Then the
/// polybius square would look like ...
///
///    A B C D E F
/// A| o r 0 a n g
/// B| e 1 b c d f
/// C| 2 h i j k 3
/// D| l m p 4 q s
/// E| 5 t u 6 v w
/// F| 7 x 8 y 9 z
///
/// ```
/// use cipher_crypt::keygen;
///
/// let square = keygen::polybius_square("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z",
///     ['A','B','C','D','E', 'F'], ['A','B','C','D','E', 'F']).unwrap();
///
/// assert_eq!(&'c', square.get("bd").unwrap());
/// ```
pub fn polybius_square(key: &str, column_ids: [char; 6], row_ids: [char; 6])
    -> Result<HashMap<String, char>, &'static str> {

    let unique_chars: HashMap<_, _> = key.chars().into_iter()
        .map(|c| (c, c))
        .collect();

    //Validate the key
    if key.len() != 36
    {
        return Err("The key must contain each character of the alphanumeric alphabet a-z 0-9.");
    }
    else if key.len() - unique_chars.len() > 0
    {
        return Err("The key cannot contain duplicate alphanumeric characters.");
    }
    else if !alphabet::is_alphanumeric_only(key)
    {
        return Err("The key cannot contain non-alphanumeric symbols.");
    }

    //Check that the column and row ids are valid
    if !alphabet::is_alphabetic_only(&column_ids.iter().cloned().collect::<String>()) ||
        !alphabet::is_alphabetic_only(&row_ids.iter().cloned().collect::<String>())
    {
        return Err("The column or row ids cannot contain non-alphanumeric symbols.");
    }

    let mut polybius_square = HashMap::new();
    let mut values = key.chars().into_iter();

    for r in 0..6 {
        for c in 0..6 {
            let k = String::from(row_ids[r].to_string() + &column_ids[c].to_string());
            let v = values.next().expect("alphabet square is invalid");

            polybius_square.insert(k.to_lowercase(), v.to_ascii_lowercase());
            polybius_square.insert(k.to_uppercase(), v.to_ascii_uppercase());
        }
    }

    Ok(polybius_square)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polybius_hashmap_order(){
        let p = polybius_square("abcdefghijklmnopqrstuvwxyz0123456789",
        ['a', 'b', 'c', 'd', 'e', 'f'], ['a', 'b', 'c', 'd', 'e', 'f']).unwrap();

        assert_eq!(&'a', p.get("aa").unwrap()); assert_eq!(&'c', p.get("ac").unwrap());
        assert_eq!(&'e', p.get("ae").unwrap()); assert_eq!(&'h', p.get("bb").unwrap());
        assert_eq!(&'z', p.get("eb").unwrap());
    }

    #[test]
    fn polybius_duplicate_characters(){
        assert!(polybius_square("abcdefghijklnnopqrstuvwxyz0123456789",
        ['a', 'b', 'c', 'd', 'e', 'f'], ['a', 'b', 'c', 'd', 'e', 'f']).is_err());
    }

    #[test]
    fn polybius_missing_characters(){
        assert!(polybius_square("adefghiklnnopqrstuvwxyz", ['a', 'b', 'c', 'd', 'e', 'f'],
        ['a', 'b', 'c', 'd', 'e', 'f']).is_err());
    }

    #[test]
    fn polybius_non_alpha_characters(){
        assert!(polybius_square("abcd@#!ghiklnnopqrstuvwxyz0123456789",
        ['a', 'b', 'c', 'd', 'e', 'f'], ['a', 'b', 'c', 'd', 'e', 'f']).is_err());
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
