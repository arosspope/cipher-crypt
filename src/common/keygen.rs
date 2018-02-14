//! This module contains functions for the generation of keys.
//!
use std::collections::HashMap;
use super::alphabet;
use super::alphabet::{Alphabet, ALPHANUMERIC, STANDARD};

/// Generates a scrambled alphabet using a key phrase for a given alphabet type.
/// Lets consider the key `or0an3ge` for an alphanumeric alphabet. The resulting keyed alphabet
/// would be `or0an3gebcdfhijklmpqstuvwxyz12456789`.
///
/// Will return Err if invalid alphabetic symbols are within the key.
pub fn keyed_alphabet<T: Alphabet>(
    key: &str,
    alpha_type: T,
    to_uppercase: bool,
) -> Result<String, &'static str> {
    if !alpha_type.is_valid(key) {
        return Err("Invalid key. Key cannot contain non-alphabetic symbols.");
    }

    //Loop through each value in the key and add to our keyed alphabet if it isn't already there
    let mut keyed_alphabet = String::new();
    for c in key.chars() {
        if keyed_alphabet
            .chars()
            .find(|a| a.eq_ignore_ascii_case(&c))
            .is_none()
        {
            if to_uppercase {
                keyed_alphabet.push_str(&c.to_uppercase().to_string())
            } else {
                keyed_alphabet.push_str(&c.to_lowercase().to_string())
            }
        }
    }

    // Add remaining letters to the end of the keyed alphabet.
    for index in 0..alpha_type.length() {
        let c = alpha_type.get_letter(index, to_uppercase).unwrap();
        if keyed_alphabet
            .chars()
            .find(|a| a.eq_ignore_ascii_case(&c))
            .is_none()
        {
            keyed_alphabet.push(c);
        }
    }

    Ok(keyed_alphabet)
}

/// Validate a Columnar Transposition key given a specific key.
///
/// Will return `Err` if one of the following conditions is detected:
///
/// * The `key` length is = 0.
/// * The `key` contains non-alphanumeric symbols.
/// * The `key` contains duplicate characters.
pub fn columnar_key(key: &str) -> Result<Vec<(char, Vec<char>)>, &'static str> {
    let unique_chars: HashMap<_, _> = key.chars().into_iter().map(|c| (c, c)).collect();

    //Validate key
    if key.is_empty() {
        return Err("The key cannot be zero length.");
    } else if key.len() - unique_chars.len() > 0 {
        return Err("The key cannot contain duplicate alphanumeric characters.");
    } else if !ALPHANUMERIC.is_valid(key) {
        return Err("The key cannot contain non-alphanumeric symbols.");
    }

    let mut c_key: Vec<(char, Vec<char>)> = Vec::new();
    for chr in key.chars() {
        c_key.push((chr, Vec::new()));
    }

    Ok(c_key)
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
/// __ A B C D E F
/// A| o r 0 a n g
/// B| e 1 b c d f
/// C| 2 h i j k 3
/// D| l m p 4 q s
/// E| 5 t u 6 v w
/// F| 7 x 8 y 9 z
///
/// `let square = keygen::polybius_square("or0ange1bcdf2hijk3lmp4qs5tu6vw7x8y9z",
///     ['A','B','C','D','E', 'F'], ['A','B','C','D','E', 'F']).unwrap();`
///
/// `assert_eq!(&'c', square.get("bd").unwrap());`

pub fn polybius_square(
    key: &str,
    column_ids: [char; 6],
    row_ids: [char; 6],
) -> Result<HashMap<String, char>, &'static str> {
    let unique_chars: HashMap<_, _> = key.chars().into_iter().map(|c| (c, c)).collect();

    //Validate the key
    if key.len() != 36 {
        return Err("The key must contain each character of the alphanumeric alphabet a-z 0-9.");
    } else if key.len() - unique_chars.len() > 0 {
        return Err("The key cannot contain duplicate alphanumeric characters.");
    } else if !ALPHANUMERIC.is_valid(key) {
        return Err("The key cannot contain non-alphanumeric symbols.");
    }

    //Check that the column and row ids are valid
    if !STANDARD.is_valid(&column_ids.iter().cloned().collect::<String>())
        || !STANDARD.is_valid(&row_ids.iter().cloned().collect::<String>())
    {
        return Err("The column and row ids cannot contain non-alphabetic symbols.");
    }

    //We need to check that each character within the row or column is unique
    let unique_cols: HashMap<_, _> = column_ids
        .iter()
        .cloned()
        .map(|c| (c.to_ascii_lowercase(), c))
        .collect();

    let unique_rows: HashMap<_, _> = row_ids
        .iter()
        .cloned()
        .map(|c| (c.to_ascii_lowercase(), c))
        .collect();

    if column_ids.len() - unique_cols.len() > 0 || row_ids.len() - unique_rows.len() > 0 {
        return Err("The column or row ids cannot contain repeated characters.");
    }

    let mut polybius_square = HashMap::new();
    let mut values = key.chars().into_iter();

    for r in 0..6 {
        for c in 0..6 {
            let k = row_ids[r].to_string() + &column_ids[c].to_string();
            let v = values.next().expect("alphabet square is invalid");

            if alphabet::is_numeric(v) {
                //Numbers dont have case, so we just insert one entry
                polybius_square.insert(k.to_uppercase(), v.to_ascii_uppercase());
            } else {
                //Insert entry for both the upper and lowercase version of the character
                polybius_square.insert(k.to_lowercase(), v.to_ascii_lowercase());
                polybius_square.insert(k.to_uppercase(), v.to_ascii_uppercase());
            }
        }
    }

    Ok(polybius_square)
}

#[cfg(test)]
mod tests {
    use super::*;

    //Polybius tests
    #[test]
    fn polybius_hashmap_order() {
        let p = polybius_square(
            "abcdefghijklmnopqrstuvwxyz0123456789",
            ['a', 'b', 'c', 'd', 'e', 'f'],
            ['a', 'b', 'c', 'd', 'e', 'f'],
        ).unwrap();

        assert_eq!(&'a', p.get("aa").unwrap());
        assert_eq!(&'c', p.get("ac").unwrap());
        assert_eq!(&'e', p.get("ae").unwrap());
        assert_eq!(&'h', p.get("bb").unwrap());
        assert_eq!(&'z', p.get("eb").unwrap());
    }

    #[test]
    fn polybius_duplicate_characters() {
        assert!(
            polybius_square(
                "abcdefghijklnnopqrstuvwxyz0123456789",
                ['a', 'b', 'c', 'd', 'e', 'f'],
                ['a', 'b', 'c', 'd', 'e', 'f']
            ).is_err()
        );
    }

    #[test]
    fn polybius_missing_characters() {
        assert!(
            polybius_square(
                "adefghiklnnopqrstuvwxyz",
                ['a', 'b', 'c', 'd', 'e', 'f'],
                ['a', 'b', 'c', 'd', 'e', 'f']
            ).is_err()
        );
    }

    #[test]
    fn polybius_non_alpha_characters() {
        assert!(
            polybius_square(
                "abcd@#!ghiklnnopqrstuvwxyz0123456789",
                ['a', 'b', 'c', 'd', 'e', 'f'],
                ['a', 'b', 'c', 'd', 'e', 'f']
            ).is_err()
        );
    }

    #[test]
    fn polybius_repeated_column_ids() {
        assert!(
            polybius_square(
                "abcdefghijklmnopqrstuvwxyz0123456789",
                ['a', 'a', 'c', 'd', 'e', 'f'],
                ['a', 'b', 'c', 'd', 'e', 'f']
            ).is_err()
        );
    }

    #[test]
    fn polybius_repeated_row_ids() {
        assert!(
            polybius_square(
                "abcdefghijklmnopqrstuvwxyz0123456789",
                ['a', 'b', 'c', 'd', 'e', 'f'],
                ['a', 'b', 'c', 'c', 'e', 'f']
            ).is_err()
        );
    }

    //Keyed alphabet tests
    #[test]
    fn generate_numeric_alphabet() {
        let keyed_alphabet = keyed_alphabet("or0ange", ALPHANUMERIC, false).unwrap();
        assert_eq!(keyed_alphabet, "or0angebcdfhijklmpqstuvwxyz123456789");
    }

    #[test]
    fn generate_standard_alphabet() {
        let keyed_alphabet = keyed_alphabet("test", STANDARD, false).unwrap();
        assert_eq!(keyed_alphabet, "tesabcdfghijklmnopqruvwxyz");
    }

    #[test]
    fn generate_alphabet_mixed_key() {
        let keyed_alphabet = keyed_alphabet("ALphaBEt", STANDARD, false).unwrap();
        assert_eq!(keyed_alphabet, "alphbetcdfgijkmnoqrsuvwxyz");
    }

    #[test]
    fn generate_uppercase_alphabet() {
        let keyed_alphabet = keyed_alphabet("OranGE", STANDARD, true).unwrap();
        assert_eq!(keyed_alphabet, "ORANGEBCDFHIJKLMPQSTUVWXYZ");
    }

    #[test]
    fn generate_alphabet_bad_key() {
        assert!(keyed_alphabet("bad key", STANDARD, false).is_err());
    }

    #[test]
    fn generate_alphabet_no_key() {
        let keyed_alphabet = keyed_alphabet("", STANDARD, false).unwrap();
        assert_eq!(keyed_alphabet, "abcdefghijklmnopqrstuvwxyz");
    }

    #[test]
    fn generate_alphabet_long_key() {
        let keyed_alphabet =
            keyed_alphabet("nnhhyqzabguuxwdrvvctspefmjoklii", STANDARD, true).unwrap();
        assert_eq!(keyed_alphabet, "NHYQZABGUXWDRVCTSPEFMJOKLI");
    }

    #[test]
    fn generate_columnar_key() {
        assert_eq!(
            vec![
                ('z', vec![]),
                ('e', vec![]),
                ('b', vec![]),
                ('r', vec![]),
                ('a', vec![]),
                ('s', vec![]),
            ],
            columnar_key("zebras").unwrap()
        );
    }

    #[test]
    fn generate_columnar_empty_key() {
        assert!(columnar_key("").is_err());
    }

    #[test]
    fn generate_columnar_invalid_key() {
        assert!(columnar_key("Fx !@#$").is_err());
    }
}
