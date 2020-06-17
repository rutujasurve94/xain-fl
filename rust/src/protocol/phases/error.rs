use crate::protocol::{
    coordinator::CoordinatorState,
    phases::{Idle, PhaseState, Shutdown},
    requests::Request,
    state_machine::{RoundFailed, StateMachine},
};
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Error, Debug)]
pub enum StateError {
    #[error("state failed: channel error: {0}")]
    ChannelError(&'static str),
    #[error("state failed: round error: {0}")]
    RoundError(#[from] RoundFailed),
}

impl PhaseState<StateError> {
    pub fn new(
        coordinator_state: CoordinatorState,
        request_rx: mpsc::UnboundedReceiver<Request>,
        error: StateError,
    ) -> Self {
        info!("state transition");
        Self {
            inner: error,
            coordinator_state,
            request_rx,
        }
    }

    pub async fn next(self) -> Option<StateMachine> {
        error!("state transition failed! error: {:?}", self.inner);
        let next_state = match self.inner {
            StateError::ChannelError(_) => {
                PhaseState::<Shutdown>::new(self.coordinator_state, self.request_rx).into()
            }
            _ => PhaseState::<Idle>::new(self.coordinator_state, self.request_rx).into(),
        };

        Some(next_state)
    }
}
