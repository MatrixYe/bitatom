use secp256k1::ecdsa::Signature;
use secp256k1::hashes::{sha256, Hash};
use secp256k1::{rand, PublicKey, SecretKey};
use secp256k1::{All, Message, Secp256k1};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Keypair {
    pub fn new() -> Self {
        let secp = Secp256k1::<All>::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn by_secret(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::<All>::new();
        let public_key = secret_key.public_key(&secp);
        Keypair {
            secret_key,
            public_key,
        }
    }
}

pub fn sign(keypair: &Keypair, content: &[u8]) -> Signature {
    let secp = Secp256k1::<All>::new();
    let digest = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.sign_ecdsa(message, &keypair.secret_key)
}

pub fn verify(content: &[u8], public_key: &PublicKey, sig: &Signature) -> bool {
    let secp = Secp256k1::<All>::new();
    let digest = sha256::Hash::hash(content);
    let message = Message::from_digest(digest.to_byte_array());
    secp.verify_ecdsa(message, sig, public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_creation() {
        let keypair = Keypair::new();
        // 将私钥转换为字节数组进行检查
        let secret_bytes = keypair.secret_key.secret_bytes();
        assert!(!secret_bytes.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_keypair_from_secret() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::by_secret(keypair1.secret_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(verify(message, &keypair.public_key, &signature));
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair1, message);
        assert!(!verify(message, &keypair2.public_key, &signature));
    }

    #[test]
    fn test_verify_modified_message() {
        let keypair = Keypair::new();
        let message = b"Hello, world!";
        let signature = sign(&keypair, message);
        assert!(!verify(
            b"Modified message",
            &keypair.public_key,
            &signature
        ));
    }
}
