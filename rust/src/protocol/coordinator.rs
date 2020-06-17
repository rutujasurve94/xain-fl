use std::collections::HashMap;

use sodiumoxide::{self, crypto::box_, randombytes::randombytes};

use crate::{
    crypto::{ByteObject, KeyPair},
    mask::{MaskConfig, MaskObject},
};

pub type RoundId = u64;

#[derive(Debug, Clone)]
pub struct RoundParameters {
    pub id: RoundId,
    pub sum: f64,
    pub update: f64,
    pub seed: RoundSeed,
}

#[derive(Debug)]
pub struct CoordinatorState {
    pub keys: KeyPair,
    pub round_params: RoundParameters,
    pub min_sum: usize,
    pub min_update: usize,
    pub expected_participants: usize,
    pub mask_config: MaskConfig,
}

impl CoordinatorState {
    pub fn new(config: CoordinatorConfig) -> Self {
        Self {
            keys: KeyPair::generate(),
            round_params: RoundParameters {
                id: 0,
                sum: config.initial_sum_ratio,
                update: config.initial_update_ratio,
                seed: RoundSeed::zeroed(),
            },
            min_sum: config.min_sum,
            min_update: config.min_update,
            expected_participants: config.expected_participants,
            mask_config: config.mask_config,
        }
    }
}

pub struct CoordinatorConfig {
    pub initial_sum_ratio: f64,
    pub initial_update_ratio: f64,
    pub min_sum: usize,
    pub min_update: usize,
    pub mask_config: MaskConfig,
    pub expected_participants: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A seed for a round.
pub struct RoundSeed(box_::Seed);

impl ByteObject for RoundSeed {
    /// Create a round seed from a slice of bytes. Fails if the length of the input is invalid.
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        box_::Seed::from_slice(bytes).map(Self)
    }

    /// Create a round seed initialized to zero.
    fn zeroed() -> Self {
        Self(box_::Seed([0_u8; Self::LENGTH]))
    }

    /// Get the round seed as a slice.
    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl RoundSeed {
    /// Get the number of bytes of a round seed.
    pub const LENGTH: usize = box_::SEEDBYTES;

    /// Generate a random round seed.
    pub fn generate() -> Self {
        // safe unwrap: length of slice is guaranteed by constants
        Self::from_slice_unchecked(randombytes(Self::LENGTH).as_slice())
    }
}

/// A dictionary created during the sum2 phase of the protocol. It counts the model masks
/// represented by their hashes.
pub type MaskDict = HashMap<MaskObject, usize>;

#[derive(Debug, Clone, Copy)]
pub enum Phase {
    Idle,
    Sum,
    Update,
    Sum2,
    Unmask,
    Error,
    Shutdown,
}
