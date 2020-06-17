use crate::{
    crypto::{ByteObject, SigningKeySeed},
    protocol::{
        coordinator::{CoordinatorState, RoundSeed},
        phases::{PhaseState, Sum},
        requests::Request,
        state_machine::StateMachine,
    },
};

use sodiumoxide::crypto::hash::sha256;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct Idle;

impl PhaseState<Idle> {
    pub fn new(
        coordinator_state: CoordinatorState,
        request_rx: mpsc::UnboundedReceiver<Request>,
    ) -> Self {
        info!("state transition");
        Self {
            inner: Idle,
            coordinator_state,
            request_rx,
        }
    }

    pub async fn next(mut self) -> Option<StateMachine> {
        self.update_round_thresholds();
        self.update_round_seed();
        Some(PhaseState::<Sum>::new(self.coordinator_state, self.request_rx).into())
    }

    fn update_round_thresholds(&mut self) {}

    /// Update the seed round parameter.
    fn update_round_seed(&mut self) {
        // safe unwrap: `sk` and `seed` have same number of bytes
        let (_, sk) =
            SigningKeySeed::from_slice_unchecked(self.coordinator_state.keys.secret.as_slice())
                .derive_signing_key_pair();
        let signature = sk.sign_detached(
            &[
                self.coordinator_state.round_params.seed.as_slice(),
                &self.coordinator_state.round_params.sum.to_le_bytes(),
                &self.coordinator_state.round_params.update.to_le_bytes(),
            ]
            .concat(),
        );
        // Safe unwrap: the length of the hash is 32 bytes
        self.coordinator_state.round_params.seed =
            RoundSeed::from_slice_unchecked(sha256::hash(signature.as_slice()).as_ref());
    }
}
