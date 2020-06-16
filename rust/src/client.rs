use crate::{
    crypto::ByteObject,
    participant::{Participant, Task},
    request::ClientReq,
    request::Proxy,
    service::{Handle, data::RoundParametersData},
    CoordinatorPublicKey,
    InitError,
    PetError,
    UpdateSeedDict,
};
use std::time::Duration;
use thiserror::Error;
use tokio::time;

/// Client-side errors
#[derive(Debug, Error)]
pub enum ClientError {
    /// Error starting the underlying [`Participant`]
    #[error("failed to initialise participant: {0}")]
    ParticipantInitErr(InitError),

    /// Error from the underlying [`Participant`]
    #[error("error arising from participant")]
    ParticipantErr(PetError),

    /// Error deserialising service data
    #[error("failed to deserialise service data: {0}")]
    DeserialiseErr(bincode::Error),

    #[error("network-related error: {0}")]
    NetworkErr(reqwest::Error),

    #[error("service data not ready for receiving")]
    DataNotReady,

    /// General client errors
    #[error("unexpected client error")]
    GeneralErr,
}

/// A client of the federated learning service
///
/// [`Client`] is responsible for communicating with the service, deserialising
/// its messages and delegating their processing to the underlying
/// [`Participant`].
pub struct Client {
    // TODO REMOVE
    /// Handle to the federated learning [`Service`]
    handle: Handle,

    /// The underlying [`Participant`]
    participant: Participant,

    /// Interval to poll for service data
    interval: time::Interval,

    /// Coordinator public key
    coordinator_pk: CoordinatorPublicKey,

    id: u32, // NOTE identifier for client for testing; may remove later

    // TODO replace with Proxy
    request: ClientReq,

    proxy: Proxy,
}

impl Client {
    // /// Create a new [`Client`]
    // ///
    // /// `period`: time period at which to poll for service data, in seconds.
    // /// Returns `Ok(client)` if [`Client`] `client` initialised successfully
    // /// Returns `Err(err)` if `ClientError` `err` occurred
    // pub fn new(period: u64, addr: &'static str) -> Result<Self, ClientError> {
    //     let (handle, _events) = Handle::new(); // dummy
    //     let participant = Participant::new().map_err(ClientError::ParticipantInitErr)?;
    //     Ok(Self {
    //         handle,
    //         participant,
    //         interval: time::interval(Duration::from_secs(period)),
    //         coordinator_pk: CoordinatorPublicKey::zeroed(),
    //         id: 0,
    //         request: ClientReq::new(addr),
    //     })
    // }

    /// Create a new [`Client`] with ID (useful for testing)
    ///
    /// `period`: time period at which to poll for service data, in seconds.
    /// `id`: an ID to assign to the [`Client`].
    /// Returns `Ok(client)` if [`Client`] `client` initialised successfully
    /// Returns `Err(err)` if `ClientError` `err` occurred
    pub fn new_with_id(period: u64, handle: Handle, id: u32) -> Result<Self, ClientError> {
        let participant = Participant::new().map_err(ClientError::ParticipantInitErr)?;
        Ok(Self {
            handle: handle.clone(),
            participant,
            interval: time::interval(Duration::from_secs(period)),
            coordinator_pk: CoordinatorPublicKey::zeroed(),
            id,
            request: ClientReq::new(""), // TODO remove later
            proxy: Proxy::from(handle),
        })
    }

    pub fn new_with_addr(period: u64, id: u32, addr: &'static str) -> Result<Self, ClientError> {
        let participant = Participant::new().map_err(ClientError::ParticipantInitErr)?;
        let (handle, _events) = Handle::new(); // dummy
        Ok(Self {
            handle,
            participant,
            interval: time::interval(Duration::from_secs(period)),
            coordinator_pk: CoordinatorPublicKey::zeroed(),
            id,
            request: ClientReq::new(addr), // TODO remove later
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

    /// [`Client`] duties within a round
    pub async fn during_round(&mut self) -> Result<Task, ClientError> {
        loop {
            let response = self.request.get_params().await;
            if let Ok(round_params_data_ser) = &response {
//          if let Some(round_params_data_ser) = self.handle.get_round_parameters().await {
                // deserialize to round params data
                let round_params_data: RoundParametersData = bincode::deserialize(&round_params_data_ser[..])
                    .map_err(|e| {
                        error!(
                            "failed to deserialize round parameters data: {}: {:?}",
                            e,
                            &round_params_data_ser[..],
                        );
                        ClientError::DeserialiseErr(e)
                    })?;
                // are there inner params?
                if let Some(ref round_params) = round_params_data.round_parameters {
                    // is this a new round?
                    if round_params.pk != self.coordinator_pk {
                        // new round: save coordinator pk
                        self.coordinator_pk = round_params.pk;
                        debug!(client_id = %self.id, "computing sigs and checking task");
                        let round_seed = round_params.seed.as_slice();
                        self.participant.compute_signatures(round_seed);
                        let (sum_frac, upd_frac) = (round_params.sum, round_params.update);
                        // perform duties as per my role for this round
                        break match self.participant.check_task(sum_frac, upd_frac) {
                            Task::Sum => self.summer().await,
                            Task::Update => self.updater().await,
                            Task::None => self.unselected().await,
                        };
                    }
                    trace!(client_id = %self.id, "still the same round");
                }
                // later on, also check presence of round_params_data.global_model
            }
            if let Err(req_err) = response {
                warn!(client_id = %self.id, "received an error response: {}", req_err);
            }
            debug!(client_id = %self.id, "new round params not ready, retrying.");
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


    // async fn _updater(&mut self) -> Result<Task, ClientError> {
    //     info!(client_id = %self.id, "selected to update");

    //     // currently, models are not yet supported fully; later on, we should
    //     // train a model here before polling for the sum dictionary

    //     let sum_dict_ser = loop {
    //         if let Ok(sum_dict_ser) = self.request._get_sums().await {
    //             break sum_dict_ser;
    //         }
    //         debug!(client_id = %self.id, "sum dictionary not ready, retrying.");
    //         // sums not yet ready, try again later...
    //         self.interval.tick().await;
    //     };
    //     let sum_dict: crate::SumDict = bincode::deserialize(&sum_dict_ser[..]).map_err(|e| {
    //         error!(
    //             "failed to deserialize sum dictionary: {}: {:?}",
    //             e,
    //             &sum_dict_ser[..],
    //         );
    //         ClientError::DeserialiseErr(e)
    //     })?;
    //     debug!(client_id = %self.id, "sum dictionary received, sending update message.");
    //     let upd_msg: Vec<u8> = self
    //         .participant
    //         .compose_update_message(self.coordinator_pk, &sum_dict);
    //     self.handle.send_message(upd_msg).await;

    //     info!(client_id = %self.id, "update participant completed a round");
    //     Ok(Task::Update)
    // }


//     async fn _summer(&mut self) -> Result<Task, ClientError> {
//         info!(client_id = %self.id, "selected for sum, sending sum message.");
//         let sum1_msg: Vec<u8> = self.participant.compose_sum_message(&self.coordinator_pk);
//         self.handle.send_message(sum1_msg).await;
// //        let sc = self.request.post_message(sum1_msg).await.map_err(|e| {
// //            warn!("error sending sum message: {}", e);
// //            ClientError::NetworkError(e)
// //        })?;
// //        debug!(client_id = %self.id, "status code from sending sum message: {}", sc);

//         let pk = self.participant.pk;

//         // *** keep trying until we get seeds
//         // let _seeds_ser = loop {
//         //     let reply = self.request.get_seeds(pk).await;
//         //     if let Ok(seeds_ser) = &reply {
//         //         break seeds_ser;
//         //     }
//         //     // safe unwrap: it's an Err
//         //     let _err = reply.unwrap_err();
//         //     // log err
//         //     // delay for a bit
//         // };
//         // ***

//         let seed_dict_ser = loop {
//             if let Ok(seed_dict_ser) = self.request.get_seeds(pk).await {
// //          if let Some(seed_dict_ser) = self.handle.get_seed_dict(pk).await {
//                 break seed_dict_ser;
//             }
//             debug!(client_id = %self.id, "seed dictionary not ready, retrying.");
//             // updates not yet ready, try again later...
//             self.interval.tick().await;
//         };
//         debug!(client_id = %self.id, "seed dictionary received");
//         let seed_dict: UpdateSeedDict = bincode::deserialize(&seed_dict_ser[..]).map_err(|e| {
//             error!(
//                 "failed to deserialize seed dictionary: {}: {:?}",
//                 e,
//                 &seed_dict_ser[..],
//             );
//             ClientError::DeserialiseErr(e)
//         })?;
//         debug!(client_id = %self.id, "sending sum2 message");
//         let sum2_msg: Vec<u8> = self
//             .participant
//             .compose_sum2_message(self.coordinator_pk, &seed_dict)
//             .map_err(ClientError::ParticipantErr)?;
//         self.handle.send_message(sum2_msg).await;

//         info!(client_id = %self.id, "sum participant completed a round");
//         Ok(Task::Sum)
//     }





















