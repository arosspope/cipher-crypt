use common::alphabet::ALPHABET;

pub struct ROT13 { }

impl ROT13 {
    pub fn apply(message: &str) -> String {
        let mut rotated_msg = String::new();

        for c in message.chars(){
            //Find the index of the character in the alphabet
            let idx = ALPHABET.iter().position(|&x| x == c);
            match idx {
                Some(i) => {
                    let mut si = (i + 13) % 26; //The substituted letter is simply 13 places away

                    //If the original character was uppercase we should offset our substitute index
                    //by 26 to reference the upper-half (UPPERCASE) section of the alphabet array
                    if c.is_uppercase() && si < 26 {
                        si += 26;
                    }

                    rotated_msg.push(ALPHABET[si]);
                },
                None => rotated_msg.push(c), //Push non-alphabetic chars 'as-is'
            }
        }

        rotated_msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_emoji(){
        let message = "Peace, Freedom and Liberty! 🗡️";
        let encrypted = ROT13::apply(message);
        let decrypted = ROT13::apply(&encrypted);

        assert_eq!(decrypted, message);
    }

    #[test]
    fn alphabet_encrypt(){
        let message = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let encrypted = ROT13::apply(message);
        let decrypted = ROT13::apply(&encrypted);

        assert_eq!(decrypted, message);
    }
}
