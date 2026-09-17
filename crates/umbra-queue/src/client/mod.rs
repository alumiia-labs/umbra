//! What a client keeps for its queues: the acknowledgment cursor of Part 6
//! §6.4.3, the ARQ of Part 3 §3.7, the receipt hold of Part 3 §3.5.4, and
//! the rotation schedule of Part 3 §3.2.4.

pub mod ack;
pub mod arq;
pub mod receipts;
pub mod rotation;
