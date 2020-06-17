use crate::{
    crypto::ByteObject,
    participant::{Participant, Task},
    request::Proxy,
    service::Handle,
    CoordinatorPublicKey,
    InitError,
    PetError,
};
use std::time::Duration;
use thiserror::Error;
use tokio::time;

/// Client-side errors
#[derive(Debug, Error)]
pub enum ClientError {

    #[error("failed to initialise participant: {0}")]
    ParticipantInitErr(InitError),

    #[error("error arising from participant")]
    ParticipantErr(PetError),

    #[error("failed to deserialise service data: {0}")]
    DeserialiseErr(bincode::Error),

    #[error("network-related error: {0}")]
    NetworkErr(reqwest::Error),

    #[error("service data not ready for receiving")]
    DataNotReady,

    #[error("unexpected client error")]
    GeneralErr,
}

/// A client of the federated learning service
///
/// [`Client`] is responsible for communicating with the service, deserialising
/// its messages and delegating their processing to the underlying
/// [`Participant`].
pub struct Client {

    /// The underlying [`Participant`]
    participant: Participant,

    /// Interval to poll for service data
    interval: time::Interval,

    /// Coordinator public key
    coordinator_pk: CoordinatorPublicKey,

    /// Identifier for this client
    id: u32,

    /// Proxy for the service
    proxy: Proxy,
}

impl Client {
    /// Create a new [`Client`] with a given service handle.
    ///
    /// `period`: time period at which to poll for service data, in seconds.
    /// `id`: an ID to assign to the [`Client`].
    /// `handle`: handle for communicating with the (local) service.
    /// Returns `Ok(client)` if [`Client`] `client` initialised successfully
    /// Returns `Err(err)` if `ClientError` `err` occurred
    pub fn new_with_hdl(period: u64, id: u32, handle: Handle) -> Result<Self, ClientError> {
        let participant = Participant::new().map_err(ClientError::ParticipantInitErr)?;
        Ok(Self {
            participant,
            interval: time::interval(Duration::from_secs(period)),
            coordinator_pk: CoordinatorPublicKey::zeroed(),
            id,
            proxy: Proxy::from(handle),
        })
    }

    /// Create a new [`Client`] with a given service address.
    ///
    /// `period`: time period at which to poll for service data, in seconds.
    /// `id`: an ID to assign to the [`Client`].
    /// `addr`: service address to connect to.
    /// Returns `Ok(client)` if [`Client`] `client` initialised successfully
    /// Returns `Err(err)` if `ClientError` `err` occurred
    pub fn new_with_addr(period: u64, id: u32, addr: &'static str) -> Result<Self, ClientError> {
        let participant = Participant::new().map_err(ClientError::ParticipantInitErr)?;
        Ok(Self {
            participant,
            interval: time::interval(Duration::from_secs(period)),
            coordinator_pk: CoordinatorPublicKey::zeroed(),
            id,
            proxy: Proxy::new(addr),
        })
    }

    /// Start the [`Client`] loop
    ///
    /// Returns `Err(err)` if `ClientError` `err` occurred
    /// NOTE in the future this may iterate only a fixed number of times, at the
    /// end of which this returns `Ok(())`
    pub async fn start(&mut self) -> Result<(), ClientError> {
        loop {
            // any error that bubbles up will finish off the client
            self.during_round().await?;
        }
    }

    pub async fn during_round(&mut self) -> Result<Task, ClientError> {
        debug!(client_id = %self.id, "polling for new round parameters");
        loop {
            if let Some(params_outer) = self.proxy.get_params().await? {
                if let Some(params_inner) = params_outer.round_parameters {
                    // new round?
                    if params_inner.pk != self.coordinator_pk {
                        debug!(client_id = %self.id, "new round parameters received, determining task.");
                        self.coordinator_pk = params_inner.pk;
                        let round_seed = params_inner.seed.as_slice();
                        self.participant.compute_signatures(round_seed);
                        let (sum_frac, upd_frac) = (params_inner.sum, params_inner.update);
                        #[rustfmt::skip]
                        break match self.participant.check_task(sum_frac, upd_frac) {
                            Task::Sum    => self.summer()    .await,
                            Task::Update => self.updater()   .await,
                            Task::None   => self.unselected().await,
                        };
                    }
                    // same coordinator pk
                    trace!(client_id = %self.id, "still the same round");
                } else {
                    trace!(client_id = %self.id, "inner round parameters not ready");
                }
            } else {
                trace!(client_id = %self.id, "round parameters data not ready");
            }
            debug!(client_id = %self.id, "new round parameters not ready, retrying.");
            self.interval.tick().await;
        }
    }

    /// Duties for unselected [`Client`]s
    async fn unselected(&mut self) -> Result<Task, ClientError> {
        debug!(client_id = %self.id, "not selected");
        Ok(Task::None)
    }

    /// Duties for [`Client`]s selected as summers
    async fn summer(&mut self) -> Result<Task, ClientError> {
        info!(client_id = %self.id, "selected to sum");
        let sum1_msg = self.participant.compose_sum_message(&self.coordinator_pk);
        self.proxy.post_message(sum1_msg).await?;

        debug!(client_id = %self.id, "sum message sent, polling for seed dict.");
        let ppk = self.participant.pk;
        loop {
            if let Some(seeds) = self.proxy.get_seeds(ppk).await? {
                debug!(client_id = %self.id, "seed dict received, sending sum2 message.");
                let sum2_msg = self
                    .participant
                    .compose_sum2_message(self.coordinator_pk, &seeds)
                    .map_err(|e| {
                        error!("failed to compose sum2 message with seeds: {:?}", &seeds);
                        ClientError::ParticipantErr(e)
                    })?;
                self.proxy.post_message(sum2_msg).await?;

                info!(client_id = %self.id, "sum participant completed a round");
                break Ok(Task::Sum)
            }
            // None case
            debug!(client_id = %self.id, "seed dict not ready, retrying.");
            self.interval.tick().await;
        }
    }

    /// Duties for [`Client`]s selected as updaters
    async fn updater(&mut self) -> Result<Task, ClientError> {
        info!(client_id = %self.id, "selected to update");
        debug!(client_id = %self.id, "polling for sum dict");
        loop {
            if let Some(sums) = self.proxy.get_sums().await? {
                debug!(client_id = %self.id, "sum dict received, sending update message.");
                let upd_msg = self
                    .participant
                    .compose_update_message(self.coordinator_pk, &sums);
                self.proxy.post_message(upd_msg).await?;

                info!(client_id = %self.id, "update participant completed a round");
                break Ok(Task::Update)
            }
            // None case
            debug!(client_id = %self.id, "sum dict not ready, retrying.");
            self.interval.tick().await;
        }
    }
}

