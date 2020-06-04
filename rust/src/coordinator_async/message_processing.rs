use crate::{
    coordinator::RoundSeed,
    crypto::ByteObject,
    message::{Sum2Owned, SumOwned, UpdateOwned},
    ParticipantPublicKey,
    ParticipantTaskSignature,
    PetError,
    SumParticipantPublicKey,
    UpdateParticipantPublicKey,
};
use std::{future::Future, sync::Arc};
use tokio::{
    sync::{
        broadcast,
        mpsc::{unbounded_channel, Sender, UnboundedReceiver, UnboundedSender},
    },
    time::Duration,
};

pub struct SumValidationData {
    pub sum: f64,
    pub seed: RoundSeed,
}

pub struct UpdateValidationData {
    pub sum: f64,
    pub update: f64,
    pub seed: RoundSeed,
}

// A sink to collect the results of the MessageHandler tasks.
pub struct MessageSink {
    // The minimum number of successfully validated messages.
    min_messages: usize,
    // A counter that is incremented when a message has been successfully validated.
    successful_messages: usize,
    // The channel receiver that receives the results of the MessageHandler tasks.
    sink_rx: UnboundedReceiver<Result<(), PetError>>,
    // The minimum duration to wait.
    min_duration: Duration,
    // Message collection time out.
    max_duration: Duration,
}

impl MessageSink {
    pub fn new(
        min_messages: usize,
        min_duration: Duration,
        max_duration: Duration,
    ) -> (UnboundedSender<Result<(), PetError>>, Self) {
        if max_duration < min_duration {
            panic!("max_duration must be greater than min_duration")
        };

        let (success_tx, sink_rx) = unbounded_channel();
        (
            success_tx,
            Self {
                min_messages,
                successful_messages: 0,
                sink_rx,
                min_duration,
                max_duration,
            },
        )
    }

    pub async fn collect(self) -> Result<(), PetError> {
        let MessageSink {
            min_messages,
            mut successful_messages,
            mut sink_rx,
            min_duration,
            max_duration,
        } = self;
        // Collect the results of the MessageHandler tasks. The collect future will be
        // successfully resolved when the minimum duration has been waited and when the minimum
        // number of successful validated messages has been reached.
        // The first failed MessageHandler result causes the collection to be canceled. In this
        // case the collect future will be resolved with an error.
        let min_collection_duration = async move {
            tokio::time::delay_for(min_duration).await;
            println!("waited min collection duration");
            Ok::<(), PetError>(())
        };

        let message_collection = async move {
            loop {
                let _message = sink_rx
                    .recv()
                    .await
                    // First '?' operator is applied on the result of '.recv()', the second one on
                    // the message itself (which has the type 'Result<(), PetError>').
                    .ok_or(PetError::InvalidMessage)??;

                successful_messages += 1;

                if successful_messages == min_messages {
                    break Ok::<(), PetError>(());
                }
            }
        };

        let mut max_collection_duration = tokio::time::delay_for(max_duration);

        tokio::select! {
            collection_result = async {
                tokio::try_join!(min_collection_duration, message_collection).map(|_| ())
            }=> {
                collection_result
            }
            _ = &mut max_collection_duration => {
                println!("message collection timed out!");
                Err::<(), PetError>(PetError::InvalidMessage)
            }
        }
    }
}

pub struct MessageHandler {
    // A sender through which the result of the massage validation is sent.
    sink_tx: UnboundedSender<Result<(), PetError>>,
    // We will never send anything on this channel.
    // We use this channel to keep track of which MessageHandler tasks are still alive.
    _cancel_complete_tx: Sender<()>,
    // The channel receiver that receives the cancel notification.
    notify_cancel: broadcast::Receiver<()>,
}

impl MessageHandler {
    pub fn new(
        sink_tx: UnboundedSender<Result<(), PetError>>,
        cancel_complete_tx: Sender<()>,
        notify_cancel: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            sink_tx,
            _cancel_complete_tx: cancel_complete_tx,
            notify_cancel,
        }
    }

    async fn handle_message(
        self,
        message_validation_fut: impl Future<Output = Result<(), PetError>>,
    ) {
        // Extract all fields of the MessageHandler struct. This is necessary to bypass borrow
        // issues in the tokio::select macro.
        // It is important to extract _cancel_complete_tx as well, otherwise the channel
        // will be dropped too early.
        let MessageHandler {
            sink_tx,
            _cancel_complete_tx,
            mut notify_cancel,
        } = self;

        tokio::select! {
            result = message_validation_fut => {let _ = sink_tx.send(result);}
            _ = notify_cancel.recv() => {println!("drop message validation future")}
        };

        // _cancel_complete_tx is dropped
    }
}

// Sum message validator
impl MessageHandler {
    /// Validate and handle a sum message.
    pub async fn handle_sum_message(
        self,
        coordinator_state: Arc<SumValidationData>,
        pk: ParticipantPublicKey,
        message: SumOwned,
    ) {
        let message_validation_fut = async {
            Self::validate_sum_task(&coordinator_state, &pk, &message.sum_signature)
            // async call to Redis
            // self.coordinator_state.sum_dict.insert(pk, message.ephm_pk);
        };
        self.handle_message(message_validation_fut).await;
    }

    /// Validate a sum signature and its implied task.
    fn validate_sum_task(
        coordinator_state: &Arc<SumValidationData>,
        pk: &SumParticipantPublicKey,
        sum_signature: &ParticipantTaskSignature,
    ) -> Result<(), PetError> {
        if pk.verify_detached(
            sum_signature,
            &[coordinator_state.seed.as_slice(), b"sum"].concat(),
        ) && sum_signature.is_eligible(coordinator_state.sum)
        {
            Ok(())
        } else {
            Err(PetError::InvalidMessage)
        }
    }
}

// Update message validator
impl MessageHandler {
    /// Validate and handle an update message.
    pub async fn handle_update_message(
        self,
        coordinator_state: Arc<UpdateValidationData>,
        pk: ParticipantPublicKey,
        message: UpdateOwned,
    ) {
        let message_validation_fut = async {
            let UpdateOwned {
                sum_signature,
                update_signature,
                local_seed_dict,
                masked_model,
            } = message;
            Self::validate_update_task(&coordinator_state, &pk, &sum_signature, &update_signature)

            // Try to update local seed dict first. If this fail, we do
            // not want to aggregate the model.

            // Should we perform the checks in add_local_seed_dict in the coordinator or
            // in redis?
            // self.add_local_seed_dict(&pk, &local_seed_dict)?;

            // Check if aggregation can be performed, and do it.
            //
            // self.aggregation
            //     .validate_aggregation(&masked_model)
            //     .map_err(|_| PetError::InvalidMessage)?;
            // self.aggregation.aggregate(masked_model);
        };
        self.handle_message(message_validation_fut).await;
    }

    /// Validate an update signature and its implied task.
    fn validate_update_task(
        coordinator_state: &Arc<UpdateValidationData>,
        pk: &UpdateParticipantPublicKey,
        sum_signature: &ParticipantTaskSignature,
        update_signature: &ParticipantTaskSignature,
    ) -> Result<(), PetError> {
        if pk.verify_detached(
            sum_signature,
            &[coordinator_state.seed.as_slice(), b"sum"].concat(),
        ) && pk.verify_detached(
            update_signature,
            &[coordinator_state.seed.as_slice(), b"update"].concat(),
        ) && !sum_signature.is_eligible(coordinator_state.sum)
            && update_signature.is_eligible(coordinator_state.update)
        {
            Ok(())
        } else {
            Err(PetError::InvalidMessage)
        }
    }
}

// Sum2 message validator
impl MessageHandler {
    /// Validate and handle an update message.
    pub async fn handle_sum2_message(
        self,
        coordinator_state: Arc<SumValidationData>,
        pk: ParticipantPublicKey,
        message: Sum2Owned,
    ) {
        let message_validation_fut = async {
            // if !self.sum_dict.contains_key(&pk) {
            //     return Err(PetError::InvalidMessage);
            // }
            Self::validate_sum_task(&coordinator_state, &pk, &message.sum_signature)
            // async call to Redis
            //self.add_mask(&pk, message.mask).unwrap();
        };
        self.handle_message(message_validation_fut).await;
    }
}