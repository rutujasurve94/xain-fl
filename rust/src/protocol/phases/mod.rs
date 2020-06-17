mod error;
mod idle;
mod shutdown;
mod sum;
mod sum2;
mod unmask;
mod update;

pub use self::{
    error::StateError,
    idle::Idle,
    shutdown::Shutdown,
    sum::Sum,
    sum2::Sum2,
    unmask::Unmask,
    update::Update,
};

use crate::{
    protocol::{coordinator::CoordinatorState, requests::Request},
    PetError,
};

use tokio::sync::{mpsc, oneshot};

pub struct PhaseState<S> {
    // Inner state
    inner: S,
    // Coordinator state
    coordinator_state: CoordinatorState,
    // Request receiver halve
    request_rx: mpsc::UnboundedReceiver<Request>,
}

// Functions that are available to all states
impl<S> PhaseState<S> {
    /// Receives the next [`Request`].
    /// Returns [`StateError::ChannelError`] when all sender halve have been dropped.
    async fn next_request(&mut self) -> Result<Request, StateError> {
        debug!("received new message");
        self.request_rx.recv().await.ok_or(StateError::ChannelError(
            "all message senders have been dropped!",
        ))
    }

    /// Handle an invalid request.
    fn handle_invalid_message(response_tx: oneshot::Sender<Result<(), PetError>>) {
        debug!("invalid message");
        // `send` returns an error if the receiver halve has already been dropped. This means that
        // the receiver is not interested in the response of the request. Therefore the error is
        // ignored.
        let _ = response_tx.send(Err(PetError::InvalidMessage));
    }
}
