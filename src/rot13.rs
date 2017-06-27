use common::alphabet;

pub struct ROT13;

impl ROT13 {
    pub fn apply(message: &str) -> String {
        alphabet::mono_substitute(message, |i| (i + 13) % 26)
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
