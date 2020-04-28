use super::ByteObject;

use sodiumoxide::crypto::hash::sha256;

use derive_more::{AsMut, AsRef, From};

#[derive(
    AsRef,
    AsMut,
    From,
    Serialize,
    Deserialize,
    Hash,
    Eq,
    Ord,
    PartialEq,
    Copy,
    Clone,
    PartialOrd,
    Debug,
)]
pub struct Sha256(sha256::Digest);

impl ByteObject for Sha256 {
    fn zeroed() -> Self {
        Self(sha256::Digest([0_u8; sha256::DIGESTBYTES]))
    }

    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn from_slice(bytes: &[u8]) -> Option<Self> {
        sha256::Digest::from_slice(bytes).map(Self)
    }
}

impl Sha256 {
    pub fn digest(m: &[u8]) -> Self {
        Self(sha256::hash(m))
    }
}