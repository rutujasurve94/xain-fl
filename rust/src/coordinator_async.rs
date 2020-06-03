use std::{
    collections::{HashMap, VecDeque},
    default::Default,
    sync::Arc,
};

use sodiumoxide::{self};

use crate::{
    coordinator::{MaskDict, ProtocolEvent, RoundSeed},
    crypto::ByteObject,
    mask::{Aggregation, BoundType, DataType, GroupType, MaskConfig, ModelType},
    message::{MessageOpen, MessageOwned, PayloadOwned},
    message_processing::{MessageSink, MessageValidator, SumValidationData},
    CoordinatorPublicKey,
    CoordinatorSecretKey,
    InitError,
    PetError,
    SeedDict,
    SumDict,
};
use tokio::{
    sync::{broadcast, mpsc},
    time::Duration,
};

pub enum StateMachine {
    Start(State<Start>),
    Idle(State<Idle>),
    Sum(State<Sum>),
    Update(State<Update>),
    Sum2(State<Sum2>),
    Error(State<Error>),
}

impl StateMachine {
    pub async fn next(self) -> Self {
        match self {
            StateMachine::Start(val) => val.next(),
            StateMachine::Idle(val) => val.next().await,
            StateMachine::Sum(val) => val.next().await,
            StateMachine::Update(val) => val.next().await,
            StateMachine::Sum2(val) => val.next().await,
            StateMachine::Error(val) => val.next().await,
        }
    }
}

#[derive(Debug)]
pub struct Start;
#[derive(Debug)]
pub struct Idle;
#[derive(Debug)]
pub struct Sum;
#[derive(Debug)]
pub struct Update {
    sum_dict: Option<Arc<SumDict>>,
}
#[derive(Debug)]
pub struct Sum2;
#[derive(Debug)]
pub struct Error;

// error state

#[derive(Debug)]
pub struct State<S> {
    _inner: S,
    // coordinator state
    coordinator_state: CoordinatorState,
    // message rx
    message_rx: tokio::sync::mpsc::UnboundedReceiver<()>,
}

// Functions that are available for all states
impl<S> State<S> {
    fn message_opener(&self) -> MessageOpen<'_, '_> {
        MessageOpen {
            recipient_pk: &self.coordinator_state.pk,
            recipient_sk: &self.coordinator_state.sk,
        }
    }

    fn message_open(&self, message: Vec<u8>) -> Result<MessageOwned, PetError> {
        self.message_opener()
            .open(&message)
            .map_err(|_| PetError::InvalidMessage)
    }

    async fn next_message(&mut self) -> Result<MessageOwned, PetError> {
        let message = match self.message_rx.recv().await {
            Some(message) => message,
            None => panic!("all message senders dropped!"),
        };
        println!("New Message!");
        self.message_open(vec![1, 2, 34]) // dummy value
    }
}

impl State<Start> {
    pub fn new() -> Result<(tokio::sync::mpsc::UnboundedSender<()>, StateMachine), InitError> {
        // crucial: init must be called before anything else in this module
        sodiumoxide::init().or(Err(InitError))?;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        Ok((
            tx,
            StateMachine::Start(State {
                _inner: Start,
                coordinator_state: CoordinatorState {
                    seed: RoundSeed::generate(),
                    ..Default::default()
                },
                message_rx: rx,
            }),
        ))
    }

    pub fn next(self) -> StateMachine {
        StateMachine::Idle(State {
            _inner: Idle,
            coordinator_state: self.coordinator_state,
            message_rx: self.message_rx,
        })
    }
}

impl State<Sum> {
    pub async fn next(mut self) -> StateMachine {
        println!("Sum phase!");
        match self.run().await {
            Ok(sum_dict) => StateMachine::Update(State {
                _inner: Update {
                    sum_dict: Some(Arc::new(sum_dict)),
                },
                coordinator_state: self.coordinator_state,
                message_rx: self.message_rx,
            }),
            Err(_) => StateMachine::Error(State {
                _inner: Error {},
                coordinator_state: self.coordinator_state,
                message_rx: self.message_rx,
            }),
        }
    }

    async fn run(&mut self) -> Result<SumDict, PetError> {
        let mut phase_timeout = tokio::time::delay_for(tokio::time::Duration::from_secs(1000));
        let (notify_cancel, _) = broadcast::channel::<()>(1);
        let (_cancel_complete_tx, mut cancel_complete_rx) = mpsc::channel::<()>(1);
        let (sink_tx, sink) = MessageSink::new(12, Duration::from_secs(5));

        let sum_validation_data = Arc::new(SumValidationData {
            seed: self.coordinator_state.seed.clone(),
            sum: self.coordinator_state.sum,
        });

        let phase_result = tokio::select! {
            stream_result = async {
                loop {
                    let message = self.next_message().await?;

                    let participant_pk = message.header.participant_pk;
                    let sum_message = match message.payload {
                        PayloadOwned::Sum(msg) => msg,
                        _ => return Err(PetError::InvalidMessage),
                    };

                    let message_validator = MessageValidator::new(sink_tx.clone(), _cancel_complete_tx.clone(), notify_cancel.subscribe());
                    let handle_fut = message_validator.handle_sum_message(sum_validation_data.clone(), participant_pk, sum_message);
                    tokio::spawn(async move { handle_fut.await });
                };
            } => {
                println!("something went wrong!");
                stream_result
            }
            sink_result = sink.collect() => {
                sink_result
            }
            _ = &mut phase_timeout => {
                println!("phase timed out");
                Err::<(), PetError>(PetError::InvalidMessage)
            }
        };

        // Drop the notify_cancel sender. By dropping the sender, all receivers will receive a
        // RecvError.
        drop(notify_cancel);

        // Wait until all MessageValidator tasks have been resolved/canceled.
        // (After all senders of this channel are dropped, which mean that all
        // MessageValidator have been dropped, the receiver of this channel will receive None).
        drop(_cancel_complete_tx);
        let _ = cancel_complete_rx.recv().await;

        // Return in case of an error
        phase_result?;
        // otherwise fetch and return the sum_dict from redis?
        Ok(HashMap::new())
    }
}

impl State<Update> {
    pub async fn next(self) -> StateMachine {
        StateMachine::Sum2(State {
            _inner: Sum2 {},
            coordinator_state: self.coordinator_state,
            message_rx: self.message_rx,
        })
    }
}

impl State<Sum2> {
    pub async fn next(self) -> StateMachine {
        StateMachine::Idle(State {
            _inner: Idle {},
            coordinator_state: self.coordinator_state,
            message_rx: self.message_rx,
        })
    }
}

impl State<Idle> {
    pub async fn next(self) -> StateMachine {
        println!("Idle phase!");
        StateMachine::Sum(State {
            _inner: Sum {},
            coordinator_state: self.coordinator_state,
            message_rx: self.message_rx,
        })
    }
}

impl State<Error> {
    pub async fn next(self) -> StateMachine {
        println!("Error phase!");
        StateMachine::Idle(State {
            _inner: Idle {},
            coordinator_state: self.coordinator_state,
            message_rx: self.message_rx,
        })
    }
}

#[derive(Debug)]
pub struct CoordinatorState {
    pk: CoordinatorPublicKey, // 32 bytes
    sk: CoordinatorSecretKey, // 32 bytes

    // round parameters
    sum: f64,
    update: f64,
    seed: RoundSeed,
    min_sum: usize,
    min_update: usize,

    // round dictionaries
    /// Dictionary built during the sum phase.
    sum_dict: SumDict,
    /// Dictionary built during the update phase.
    seed_dict: SeedDict,
    /// Dictionary built during the sum2 phase.
    mask_dict: MaskDict,

    /// The masking configuration
    mask_config: MaskConfig,

    /// The aggregated masked model being built in the current round.
    aggregation: Aggregation,

    /// Events emitted by the state machine
    events: VecDeque<ProtocolEvent>,
}

impl Default for CoordinatorState {
    fn default() -> Self {
        let pk = CoordinatorPublicKey::zeroed();
        let sk = CoordinatorSecretKey::zeroed();
        let sum = 0.01_f64;
        let update = 0.1_f64;
        let seed = RoundSeed::zeroed();
        let min_sum = 1_usize;
        let min_update = 3_usize;
        let sum_dict = SumDict::new();
        let seed_dict = SeedDict::new();
        let mask_dict = MaskDict::new();
        let events = VecDeque::new();
        let mask_config = MaskConfig {
            group_type: GroupType::Prime,
            data_type: DataType::F32,
            bound_type: BoundType::B0,
            model_type: ModelType::M3,
        };
        let aggregation = Aggregation::new(mask_config);
        Self {
            pk,
            sk,
            sum,
            update,
            seed,
            min_sum,
            min_update,
            sum_dict,
            seed_dict,
            mask_dict,
            events,
            mask_config,
            aggregation,
        }
    }
}

// async fn run() {
//     let (_, state_start) = State::new().unwrap(); // Start
//     let mut state_idle = state_start.next(); // Idle

//     loop {
//         let state_sum = state_idle.next().await; // Sum
//         let state_update = state_sum.next().await; // Update
//         let state_sum2 = state_update.next().await; // Sum2
//         state_idle = state_sum2.next().await; // Idle
//     }
// }

// async_closure not stable yet
// let test = async move |message: MessageOwned,
//                        sink: mpsc::UnboundedSender<Result<(), PetError>>,
//                        _cancel_complete_tx: mpsc::Sender<()>,
//                        notify_cancel: broadcast::Sender<()>| {
//     let participant_pk = message.header.participant_pk;
//     let sum_message = match message.payload {
//         PayloadOwned::Sum(msg) => msg,
//         _ => return Err(PetError::InvalidMessage),
//     };
//     let message_validator = MessageValidator::new(
//         sink_tx.clone(),
//         _cancel_complete_tx.clone(),
//         notify_cancel.subscribe(),
//     );
//     let handle_fut = message_validator.handle_sum_message(
//         sum_validation_data.clone(),
//         participant_pk,
//         sum_message,
//     );
//     tokio::spawn(async move { handle_fut.await });
//     Ok(())
// };
