use crate::{
    mask::UnmaskingError,
    protocol::{
        coordinator::CoordinatorState,
        phases::{Idle, PhaseState, Shutdown, StateError, Sum, Sum2, Unmask, Update},
        requests::Request,
    },
    InitError,
};

use derive_more::From;
use thiserror::Error;
use tokio::sync::mpsc;

/// Error that occurs when unmasking of the global model fails
#[derive(Error, Debug, Eq, PartialEq)]
pub enum RoundFailed {
    #[error("ambiguous masks were computed by the sum participants")]
    AmbiguousMasks,
    #[error("no mask found")]
    NoMask,
    #[error("unmasking error: {0}")]
    Unmasking(#[from] UnmaskingError),
}

#[derive(From)]
pub enum StateMachine {
    Idle(PhaseState<Idle>),
    Sum(PhaseState<Sum>),
    Update(PhaseState<Update>),
    Sum2(PhaseState<Sum2>),
    Unmask(PhaseState<Unmask>),
    Error(PhaseState<StateError>),
    Shutdown(PhaseState<Shutdown>),
}

impl StateMachine {
    /// Create a new state machine with the initial state `Idle`.
    /// Fails if there is insufficient system entropy to generate secrets.
    pub fn new(
        coordinator_state: CoordinatorState,
    ) -> Result<(mpsc::UnboundedSender<Request>, Self), InitError> {
        // crucial: init must be called before anything else in this module
        sodiumoxide::init().or(Err(InitError))?;

        let (request_tx, request_rx) = mpsc::unbounded_channel::<Request>();
        Ok((
            request_tx,
            PhaseState::<Idle>::new(coordinator_state, request_rx).into(),
        ))
    }

    /// Move to the next state and consume the old one.
    pub async fn next(self) -> Option<Self> {
        match self {
            StateMachine::Idle(state) => state.next().await,
            StateMachine::Sum(state) => state.next().await,
            StateMachine::Update(state) => state.next().await,
            StateMachine::Sum2(state) => state.next().await,
            StateMachine::Unmask(state) => state.next().await,
            StateMachine::Error(state) => state.next().await,
            StateMachine::Shutdown(state) => state.next().await,
        }
    }

    /// Run the state machine until it shuts down.
    pub async fn run(mut self) -> Option<Self> {
        loop {
            self = self.next().await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        crypto::{generate_encrypt_key_pair, generate_signing_key_pair, ByteObject},
        mask::{
            BoundType,
            DataType,
            EncryptedMaskSeed,
            GroupType,
            MaskConfig,
            MaskObject,
            MaskSeed,
            ModelType,
        },
        protocol::{
            coordinator::{CoordinatorConfig, CoordinatorState},
            requests::{Request, Sum2Request, SumRequest, UpdateRequest},
            state_machine::StateMachine,
        },
        LocalSeedDict,
        PetError,
        SumParticipantPublicKey,
    };
    use tokio::sync::oneshot;
    use tracing_subscriber::*;

    fn enable_logging() {
        let _fmt_subscriber = FmtSubscriber::builder()
            .with_env_filter(EnvFilter::from_default_env())
            .with_ansi(true)
            .init();
    }

    fn gen_sum_request() -> (
        SumRequest,
        SumParticipantPublicKey,
        oneshot::Receiver<Result<(), PetError>>,
    ) {
        let (response_tx, response_rx) = oneshot::channel::<Result<(), PetError>>();
        let (participant_pk, _) = generate_signing_key_pair();
        let (ephm_pk, _) = generate_encrypt_key_pair();
        (
            SumRequest {
                participant_pk,
                ephm_pk,
                response_tx,
            },
            participant_pk,
            response_rx,
        )
    }

    fn gen_update_request(
        sum_pk: SumParticipantPublicKey,
    ) -> (UpdateRequest, oneshot::Receiver<Result<(), PetError>>) {
        let (response_tx, response_rx) = oneshot::channel::<Result<(), PetError>>();
        let (participant_pk, _) = generate_signing_key_pair();
        let mut local_seed_dict = LocalSeedDict::new();
        local_seed_dict.insert(sum_pk, EncryptedMaskSeed::zeroed());
        let masked_model = gen_mask();
        (
            UpdateRequest {
                participant_pk,
                local_seed_dict,
                masked_model,
                response_tx,
            },
            response_rx,
        )
    }

    fn gen_mask() -> MaskObject {
        let seed = MaskSeed::generate();
        let mask = seed.derive_mask(
            10,
            MaskConfig {
                group_type: GroupType::Prime,
                data_type: DataType::F32,
                bound_type: BoundType::B0,
                model_type: ModelType::M3,
            },
        );
        mask
    }

    fn gen_sum2_request(
        sum_pk: SumParticipantPublicKey,
    ) -> (Sum2Request, oneshot::Receiver<Result<(), PetError>>) {
        let (response_tx, response_rx) = oneshot::channel::<Result<(), PetError>>();
        let mask = gen_mask();
        (
            Sum2Request {
                participant_pk: sum_pk,
                mask,
                response_tx,
            },
            response_rx,
        )
    }

    fn is_update(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Update(_) => true,
            _ => false,
        }
    }

    fn is_sum(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Sum(_) => true,
            _ => false,
        }
    }

    fn is_sum2(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Sum2(_) => true,
            _ => false,
        }
    }

    fn is_idle(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Idle(_) => true,
            _ => false,
        }
    }

    fn is_unmask(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Unmask(_) => true,
            _ => false,
        }
    }

    fn is_error(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Error(_) => true,
            _ => false,
        }
    }

    fn is_shutdown(state_machine: &StateMachine) -> bool {
        match state_machine {
            StateMachine::Shutdown(_) => true,
            _ => false,
        }
    }

    #[tokio::test]
    async fn test_state_machine() {
        enable_logging();
        let config = CoordinatorConfig {
            initial_sum_ratio: 0.4,
            initial_update_ratio: 0.5,
            min_sum: 1,
            min_update: 3,
            mask_config: MaskConfig {
                group_type: GroupType::Prime,
                data_type: DataType::F32,
                bound_type: BoundType::B0,
                model_type: ModelType::M3,
            },
            expected_participants: 10,
        };
        let coordinator_state = CoordinatorState::new(config);
        let (request_tx, mut state_machine) = StateMachine::new(coordinator_state).unwrap();
        assert!(is_idle(&state_machine));

        state_machine = state_machine.next().await.unwrap(); // transition from init to sum state
        assert!(is_sum(&state_machine));

        let (sum_req, sum_pk, response_rx) = gen_sum_request();
        let _ = request_tx.send(Request::Sum(sum_req));

        state_machine = state_machine.next().await.unwrap(); // transition from sum to update state
        assert!(is_update(&state_machine));
        assert!(response_rx.await.is_ok());

        for _ in 0..3 {
            let (gen_update_request, _) = gen_update_request(sum_pk.clone());
            let _ = request_tx.send(Request::Update(gen_update_request));
        }
        state_machine = state_machine.next().await.unwrap(); // transition from update to sum state
        assert!(is_sum2(&state_machine));

        let (sum2_req, response_rx) = gen_sum2_request(sum_pk.clone());
        let _ = request_tx.send(Request::Sum2(sum2_req));
        state_machine = state_machine.next().await.unwrap(); // transition from sum2 to unmasked state
        assert!(response_rx.await.is_ok());
        assert!(is_unmask(&state_machine));

        state_machine = state_machine.next().await.unwrap(); // transition from unmasked to idle state
        assert!(is_idle(&state_machine));

        drop(request_tx);
        state_machine = state_machine.next().await.unwrap(); // transition from idle to sum state
        assert!(is_sum(&state_machine));

        state_machine = state_machine.next().await.unwrap(); // transition from sum to error state
        assert!(is_error(&state_machine));

        state_machine = state_machine.next().await.unwrap(); // transition from error to shutdown state
        assert!(is_shutdown(&state_machine));
        assert!(state_machine.next().await.is_none())
    }
}
