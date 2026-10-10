//! What a client keeps for its queues: the acknowledgment cursor of Part 6
//! §6.4.3, the ARQ of Part 3 §3.7, and the receipt hold of Part 3 §3.5.4.
//!
//! The rotation schedule of Part 3 §3.2.4 is not here. The client node
//! holds the one implementation, because the jitter of `NET-323` needs the
//! salt of the contact.

pub mod ack;
pub mod arq;
pub mod receipts;
