use crate::{Error, Result};
use ring::hkdf;

const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const CLIENT_INITIAL_LABEL: &[u8] = b"client in";
const SERVER_INITIAL_LABEL: &[u8] = b"server in";
const KEY_LABEL: &[u8] = b"quic key";
const IV_LABEL: &[u8] = b"quic iv";
const HP_LABEL: &[u8] = b"quic hp";
#[derive(Debug)]
pub struct PacketKey {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub hp_key: Vec<u8>,
}

#[derive(Debug)]
pub struct ConnectionSecrets {
    pub client: PacketKey,
    pub server: PacketKey,
}
pub fn derive_initial_secrets(dcid: &[u8]) -> Result<ConnectionSecrets> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT_V1);
    let initial_secret = salt.extract(dcid);
    let client_secret = hkdf_expand_label(&initial_secret, CLIENT_INITIAL_LABEL, 32)?;
    let server_secret = hkdf_expand_label(&initial_secret, SERVER_INITIAL_LABEL, 32)?;
    let client_key = derive_packet_key(&client_secret)?;
    let server_key = derive_packet_key(&server_secret)?;
    Ok(ConnectionSecrets {
        client: client_key,
        server: server_key,
    })
}
fn derive_packet_key(secret: &[u8]) -> Result<PacketKey> {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let key = hkdf_expand_label_prk(&prk, KEY_LABEL, 16)?;
    let iv = hkdf_expand_label_prk(&prk, IV_LABEL, 12)?;
    let hp_key = hkdf_expand_label_prk(&prk, HP_LABEL, 16)?;
    Ok(PacketKey { key, iv, hp_key })
}
fn hkdf_expand_label(secret: &hkdf::Prk, label: &[u8], length: usize) -> Result<Vec<u8>> {
    hkdf_expand_label_prk(secret, label, length)
}
fn hkdf_expand_label_prk(prk: &hkdf::Prk, label: &[u8], length: usize) -> Result<Vec<u8>> {
    let full_label = [b"tls13 ", label].concat();
    let mut info = Vec::new();
    info.push((length >> 8) as u8); // length (high byte)
    info.push(length as u8); // length (low byte)
    info.push(full_label.len() as u8); // label length
    info.extend_from_slice(&full_label); // label
    info.push(0); // context length (empty)
    let mut output = vec![0u8; length];

    prk.expand(&[&info], HkdfLen(length))
        .map_err(|_| Error::InvalidVarint("HKDF expand failed".to_string()))?
        .fill(&mut output)
        .map_err(|_| Error::InvalidVarint("HKDF fill failed".to_string()))?;
    Ok(output)
}
struct HkdfLen(usize);
impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub fn compute_nonce(iv: &[u8], packet_number: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let pn_bytes = packet_number.to_be_bytes();
    let nonce_len = nonce.len();

    for i in 0..8 {
        nonce[nonce_len - 8 + i] ^= pn_bytes[i];
    }

    nonce
}
/// Generate a random Connection ID
pub fn generate_connection_id(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::rng();
    (0..length).map(|_| rng.random()).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_derive_initial_secrets() {
        // Test vector from RFC 9001, Appendix A.1
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let secrets = derive_initial_secrets(&dcid).unwrap();

        assert_eq!(secrets.client.key.len(), 16);
        assert_eq!(secrets.client.iv.len(), 12);
        assert_eq!(secrets.client.hp_key.len(), 16);

        assert_eq!(secrets.server.key.len(), 16);
        assert_eq!(secrets.server.iv.len(), 12);
        assert_eq!(secrets.server.hp_key.len(), 16);
    }
    #[test]
    fn test_compute_nonce() {
        let iv = [0u8; 12];
        let nonce = compute_nonce(&iv, 1);

        assert_eq!(nonce.len(), 12);
        assert_eq!(nonce[11], 1);
    }
    #[test]
    fn test_generate_connection_id() {
        let cid1 = generate_connection_id(8);
        let cid2 = generate_connection_id(8);

        assert_eq!(cid1.len(), 8);
        assert_eq!(cid2.len(), 8);
        assert_ne!(cid1, cid2);
    }
}
