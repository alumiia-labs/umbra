//! The canonical vectors of Part 6 §6.8 for each structure this crate
//! encodes: the capsule at each bucket and each session op, the session
//! controls, the ratchet record at each frame length, the queue record at
//! each bucket with its SEND and MSG pair, the edit and delete bodies, the
//! group record and its commands, each group control type, and the
//! application bodies. Each rejection case that the section names is
//! asserted beside the vector it belongs to.
//!
//! Self-generated and not independently confirmed. The ignored test
//! `generate` writes the file; run `scripts/vectors.py` afterwards.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use std::{fs, path::PathBuf};

use serde_json::{json, Value};
use umbra_crypto::{
    group::{
        chain::EpochSecret,
        pair::{app_hash, RecordTag},
        slot, MemberKeys,
    },
    hash::sha3_256,
    kem,
    queue::QueueKey,
    ratchet::codeword::Kind,
    secret::Secret,
    sign::{SigningKey, SIGNATURE_LEN},
};
use umbra_wire::{
    admission::Admission,
    app::{
        devset::{ControlType as DevType, DeviceSetBody},
        edit::{DeleteBody, DeleteScope, EditBody},
        keys::{
            DigestBody, DigestSource, KeyChangeNotice, KeyRequest, KeyScope, KeySupply,
            SupplyStatus,
        },
        poll::{Poll, PollVote},
        recovery::RecoveryShare,
        rich::RichRecord,
        share::{ContactShare, ShareType},
        signal::{
            encode_timer, parse_timer, ReactionAction, ReactionBody, ReceiptBody, TypingState,
            TIMER_VALUES,
        },
        AppKind, AppMessage, Channel,
    },
    bucket::Bucket,
    capsule::{self, CapsuleType},
    cell::{pad_body, unpad_body, CellCommand},
    command::{
        iblob_parse, iblob_payload, iput_parse, iput_payload, Cmd, Command, IdsPayload, NewPayload,
    },
    descriptor::{class, AttachmentBody, ChunkRef, FileDescriptor, Level, CHUNK_SIZE},
    directory,
    group::{
        control::{
            Chain, ControlType, GrantingEpoch, GroupControl, GroupInvitation, GroupMemberEntry,
            InvitationAdmit, InvitationStage, JoinRecord, MemberKemKey, MemberKeys as JoinKeys,
            ModAction, ModerationEpoch, PlainEpoch, PlainOp, RekeyRecord, ReplicaRef, Role,
            RosterSnapshot, SnapshotNotice, PRESENCE,
        },
        record::{
            seal_content, Carrier, ContentPlain, EpochKeyBody, GroupQueueRecord, KemSlot,
            SlotPayload, Tags,
        },
        GkeyPayload, GseqPayload,
    },
    nack::{NackPayload, Reason},
    queue::{self, L6Kind},
    ratchet::{PqFrame, RatchetRecord},
    session::{SessionControl, SessionFrame},
};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/umbra/wire.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Rng(u8);
impl umbra_crypto::rand_core::TryRng for Rng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}
impl umbra_crypto::rand_core::TryCryptoRng for Rng {}

const GROUP_ID: [u8; 32] = [0x67; 32];

fn framing() -> Value {
    let mut cells = Vec::new();
    for bucket in Bucket::ALL {
        let mut body = vec![0u8; bucket.body_len()];
        pad_body(bucket, CellCommand::Data, b"content", &mut body).unwrap();
        assert_eq!(unpad_body(&body).unwrap().1, b"content");
        let mut cell = vec![0x11u8; 32];
        cell.extend_from_slice(&body);
        let frame = SessionFrame {
            session_id: [0x22; 8],
            seq: 5,
            resend: false,
            cell: &cell,
        };
        let mut frame_bytes = vec![0u8; cell.len() + 12];
        frame.encode(&mut frame_bytes).unwrap();
        let mut caps = vec![0u8; frame_bytes.len() + 6];
        capsule::encode(CapsuleType::Cell, &frame_bytes, &mut caps).unwrap();
        cells.push(json!({
            "bucket": bucket.cell_len(),
            "capsule_header": hex(&caps[..6]),
            "session_frame_header": hex(&frame_bytes[..12]),
            "body_head": hex(&body[..12]),
            "body_tail": hex(&body[body.len() - 4..]),
        }));
    }
    // WIR-295: a type of 0x0B59, a 4-byte type, a 2-byte length, a length of 525.
    let mut bad = vec![0x4B, 0x59, 0x80, 0, 2, 0x0C];
    bad.extend_from_slice(&[0u8; 524]);
    assert!(capsule::parse(&bad).is_err());
    // The same bytes under 0x0B52 parse, thus the type alone rejects them.
    bad[1] = 0x52;
    assert!(capsule::parse(&bad).is_ok());
    // WIR-538: a receipt and a relay hello of the correct length, on a
    // client link and on a link between two relays.
    for (kind, len) in [
        (CapsuleType::Receipt, capsule::RECEIPT_LEN),
        (CapsuleType::RelayHello, capsule::RELAY_HELLO_LEN),
    ] {
        let mut held = vec![0u8; capsule::HEADER_LEN + len];
        capsule::encode(kind, &vec![0u8; len], &mut held).unwrap();
        assert!(capsule::parse_on(&held, capsule::Link::Client).is_err());
        assert_eq!(
            capsule::parse_on(&held, capsule::Link::Relays).unwrap().0,
            kind
        );
    }
    assert!(capsule::parse(&[0x80, 0, 0x0B, 0x52, 0x80, 0, 2, 0x0C]).is_err());
    assert!(capsule::parse(&[0x4B, 0x52, 0x42, 0x0C]).is_err());
    let mut bad = vec![0x4B, 0x52, 0x80, 0, 2, 0x0D];
    bad.extend_from_slice(&[0u8; 525]);
    assert!(capsule::parse(&bad).is_err());

    let secret = Secret::new([0x33; 32]);
    let id = [0x22; 8];
    let mut ops = Vec::new();
    let open = SessionControl::Open {
        session_id: id,
        session_secret: Secret::new([0x33; 32]),
    };
    let resume = SessionControl::resume(&secret, id, 1, 5, 7);
    let close = SessionControl::Close { session_id: id };
    let destroy = SessionControl::Destroy {
        circ_id: [0x44; 16],
    };
    let pause = SessionControl::Pause { session_id: id };
    let paused = SessionControl::Paused { session_id: id };
    let circuit_pause = SessionControl::CircuitPause {
        circ_id: [0x44; 16],
    };
    for (name, op) in [
        ("open", open),
        ("resume", resume),
        ("close", close),
        ("destroy", destroy),
        ("pause", pause),
        ("paused", paused),
        ("circuit_pause", circuit_pause),
    ] {
        let mut buf = [0u8; 41];
        let n = op.encode(&mut buf).unwrap();
        let mut caps = vec![0u8; n + 6];
        capsule::encode(CapsuleType::Session, &buf[..n], &mut caps).unwrap();
        ops.push(json!({ "op": name, "capsule": hex(&caps) }));
    }
    let parsed = SessionControl::parse(&{
        let mut b = [0u8; 37];
        SessionControl::resume(&secret, id, 1, 5, 7)
            .encode(&mut b)
            .unwrap();
        b
    })
    .unwrap();
    assert_eq!(parsed.verify_resume(&secret, &id, 0).unwrap(), (1, 5, 7));
    assert!(parsed.verify_resume(&secret, &id, 1).is_err());
    json!({ "cells": cells, "session_ops": ops, "session_secret": hex(&[0x33; 32]) })
}

fn ratchet_records() -> Value {
    let mut out = Vec::new();
    let cases: [(Option<(u32, Kind, u16, usize)>, u16); 6] = [
        (None, 0),
        (Some((1, Kind::Header, 0, 32)), 1),
        (Some((255, Kind::Header, 0, 64)), 65_535),
        (Some((256, Kind::Header, 0, 64)), 0),
        (Some((7, Kind::Parity, 36, 64)), 2),
        (Some((7, Kind::Header, 0, 128)), 3),
    ];
    for (frame, send_index) in cases {
        let chunk = vec![0x44u8; frame.map_or(0, |f| f.3)];
        let rec = RatchetRecord {
            ctx: umbra_crypto::ratchet::dr::Ctx {
                session_tag: [0x55, 0x66],
                send_index,
            },
            hdr_nonce: [0x77; 12],
            hdr_ct: &[0x88; 56],
            pq_frame: frame.map(|(epoch, kind, index, _)| PqFrame {
                epoch,
                kind,
                index,
                chunk: &chunk,
            }),
            body_nonce: [0x99; 12],
            body_ct: &[0xAA; 24],
        };
        let mut buf = vec![0u8; 300];
        let n = rec.encode(&mut buf).unwrap();
        assert_eq!(RatchetRecord::parse(&buf[..n]).unwrap(), rec);
        out.push(json!({
            "pq_frame_len": frame.map_or(0, |f| f.3 + 7),
            "epoch": frame.map(|f| f.0),
            "kind": frame.map(|f| f.1 as u8),
            "index": frame.map(|f| f.2),
            "send_index": send_index,
            "record": hex(&buf[..n]),
        }));
    }
    // WIR-299: a pq_frame_len of 68, an index of 41 at width 64, a version of
    // 0x01, and a kind of 0x05.
    let mut buf = vec![0u8; 300];
    let base = RatchetRecord {
        ctx: umbra_crypto::ratchet::dr::Ctx {
            session_tag: [0, 0],
            send_index: 0,
        },
        hdr_nonce: [0; 12],
        hdr_ct: &[0; 56],
        pq_frame: Some(PqFrame {
            epoch: 1,
            kind: Kind::Header,
            index: 0,
            chunk: &[0; 64],
        }),
        body_nonce: [0; 12],
        body_ct: &[0; 16],
    };
    let n = base.encode(&mut buf).unwrap();
    for (offset, value) in [(73usize, 68u8), (80, 41), (0, 0x01), (78, 0x05)] {
        let mut bad = buf[..n].to_vec();
        bad[offset] = value;
        assert!(RatchetRecord::parse(&bad).is_err());
    }
    json!(out)
}

fn queue_records() -> Value {
    let key = QueueKey::derive(&Secret::new([0x01; 32]), &[0x02; 32]);
    let mut out = Vec::new();
    for bucket in Bucket::ALL {
        let inner = vec![0x42u8; bucket.l7_record()];
        let mut send = vec![0u8; bucket.l6_record()];
        queue::seal(
            &key,
            [0x03; 12],
            &[0x02; 32],
            L6Kind::Ratchet,
            &inner,
            bucket,
            &mut send,
        )
        .unwrap();
        let mut msg = vec![0u8; bucket.l5_payload()];
        queue::msg_from_send(9, &send, bucket, &mut msg).unwrap();
        let send_cmd = Command {
            cmd: Cmd::Send,
            corr_id: [0x04; 16],
            queue_id: [0x05; 32],
            auth: [0x06; 32],
            payload: &send,
        };
        let msg_cmd = Command {
            cmd: Cmd::Msg,
            payload: &msg,
            ..send_cmd
        };
        // WIR-098 to WIR-100: both payload_len values, one bucket.
        assert_eq!(send_cmd.len(), bucket.command_area() - 4);
        assert_eq!(msg_cmd.len(), bucket.command_area());
        let mut plain = vec![0u8; bucket.l6_record()];
        let (kind, len) = queue::open(&key, &[0x02; 32], &send, bucket, &mut plain).unwrap();
        assert_eq!((kind, len), (L6Kind::Ratchet, inner.len()));
        out.push(json!({
            "bucket": bucket.cell_len(),
            "send_payload_len": send.len(),
            "msg_payload_len": msg.len(),
            "inner_len": inner.len(),
            "send_head": hex(&send[..16]),
            "send_tag": hex(&send[send.len() - 16..]),
            "msg_head": hex(&msg[..20]),
        }));
    }
    json!({ "qe": hex(&[0x01; 32]), "sender_id": hex(&[0x02; 32]), "nonce": hex(&[0x03; 12]), "rows": out })
}

fn edit_and_delete() -> Value {
    let mut buf = vec![0u8; 400];
    let text138 = "e".repeat(138);
    let edit_max = EditBody {
        target: [0x10; 16],
        new_body: &text138,
    };
    let n = edit_max.encode(&mut buf).unwrap();
    assert_eq!(n + 30, Bucket::B0.app_default_chunk());
    let edit_hex = hex(&buf[..n]);
    let del = DeleteBody {
        scope: DeleteScope::OtherParty,
        targets: (0..9u8).map(|i| [i; 16]).collect(),
    };
    let n = del.encode(&mut buf).unwrap();
    assert_eq!(n, 146);
    let del_hex = hex(&buf[..n]);
    // WIR-102 rejections.
    assert!(EditBody::parse(&[1; 17]).is_err());
    let mut bad_utf8 = [1u8; 18];
    bad_utf8[17] = 0xFF;
    assert!(EditBody::parse(&bad_utf8).is_err());
    assert!(DeleteBody::parse(&[1, 2]).is_err());
    let mut ten = vec![1u8, 2];
    for i in 0..10u8 {
        ten.extend_from_slice(&[i; 16]);
    }
    assert!(DeleteBody::parse(&ten).is_err());
    let mut swapped = vec![1u8, 2];
    swapped.extend_from_slice(&[2; 16]);
    swapped.extend_from_slice(&[1; 16]);
    assert!(DeleteBody::parse(&swapped).is_err());
    let mut repeated = vec![1u8, 2];
    repeated.extend_from_slice(&[1; 16]);
    repeated.extend_from_slice(&[1; 16]);
    assert!(DeleteBody::parse(&repeated).is_err());

    // WIR-101: the minimum length of each variable field.
    let edit_min = EditBody {
        target: [0x10; 16],
        new_body: "e",
    };
    let n = edit_min.encode(&mut buf).unwrap();
    assert_eq!(n, 18);
    let edit_min_hex = hex(&buf[..n]);
    let del_min = DeleteBody {
        scope: DeleteScope::OwnDevices,
        targets: vec![[0x11; 16]],
    };
    let n = del_min.encode(&mut buf).unwrap();
    assert_eq!(n, 18);
    let del_min_hex = hex(&buf[..n]);

    // An edit of a group text. The text is the `app` of a group record,
    // and the edit names its `msg_id`.
    let message = |kind: AppKind, id: u8, body: &[u8]| {
        let msg = AppMessage {
            kind,
            msg_id: [id; 16],
            sent_at: 1_700_000_000_000,
            body,
        };
        let mut out = vec![0u8; msg.len()];
        msg.encode(&mut out).unwrap();
        AppMessage::parse(&out, Channel::Group).unwrap();
        out
    };
    let group_text = message(AppKind::Text, 0x12, b"first");
    let edit = EditBody {
        target: [0x12; 16],
        new_body: "second",
    };
    let n = edit.encode(&mut buf).unwrap();
    let group_edit = message(AppKind::Edit, 0x13, &buf[..n]);
    let group_after = message(AppKind::Text, 0x12, edit.new_body.as_bytes());

    // An edit of a reply. WIR-465: the reply target, the thread root, and
    // the mention list do not change, and the inner text does.
    let reply = RichRecord {
        reply_target: [0x14; 16],
        thread_root: [0x15; 16],
        forward_depth: 0,
        mentions: vec![[0x16; 16], [0x17; 16]],
        inner_kind: AppKind::Text,
        inner_body: b"first",
    };
    let n = reply.encode(Channel::Group, &mut buf).unwrap();
    let reply_before = message(AppKind::Rich, 0x18, &buf[..n]);
    let edit = EditBody {
        target: [0x18; 16],
        new_body: "second",
    };
    let n = edit.encode(&mut buf).unwrap();
    let reply_edit = message(AppKind::Edit, 0x19, &buf[..n]);
    let edited = RichRecord {
        inner_body: edit.new_body.as_bytes(),
        ..reply.clone()
    };
    let n = edited.encode(Channel::Group, &mut buf).unwrap();
    let reply_after = message(AppKind::Rich, 0x18, &buf[..n]);
    let after = AppMessage::parse(&reply_after, Channel::Group).unwrap();
    let after = RichRecord::parse(after.body, Channel::Group).unwrap();
    assert_eq!(after.reply_target, reply.reply_target);
    assert_eq!(after.thread_root, reply.thread_root);
    assert_eq!(after.mentions, reply.mentions);
    assert_eq!(after.inner_body, b"second");

    json!({
        "edit_at_138": edit_hex, "delete_at_9": del_hex,
        "edit_at_1": edit_min_hex, "delete_at_1": del_min_hex,
        "edit_of_group_text": {
            "target": hex(&group_text), "edit": hex(&group_edit), "after": hex(&group_after),
        },
        "edit_of_reply": {
            "target": hex(&reply_before), "edit": hex(&reply_edit), "after": hex(&reply_after),
        },
    })
}

fn group_records() -> Value {
    let members: Vec<MemberKeys> = (0..3u8)
        .map(|i| MemberKeys::from_seed(&Secret::new([0x61 + i; 32])))
        .collect();
    let secret = EpochSecret::new(Secret::new([0x6b; 32]));
    let state = secret.start(&GROUP_ID, 1, 497_000);
    let slot_index = 497_002;
    let record_key = state.record_key(slot_index).unwrap();

    // Dense at 3 members with a 350-byte text, in B1.
    let text = AppMessage {
        kind: AppKind::Text,
        msg_id: [0x0a; 16],
        sent_at: 1_700_000_000_000,
        body: &[b't'; 350],
    };
    let mut app = vec![0u8; text.len()];
    text.encode(&mut app).unwrap();
    let hash = app_hash(&app);
    let fields = RecordTag {
        group_id: &GROUP_ID,
        epoch: 1,
        slot: slot_index,
        sender_index: 0,
        counter: 1,
        roster_epoch: 1,
        app_hash: &hash,
    };
    let mut tags = vec![0u8; 36];
    for j in 1..3 {
        let key = members[0]
            .pair_key(&members[j].pair_public(), &GROUP_ID)
            .unwrap();
        tags[j * 12..(j + 1) * 12].copy_from_slice(&key.record_tag(&fields));
    }
    let plain = ContentPlain {
        sender_index: 0,
        counter: 1,
        roster_epoch: 1,
        tags: Tags::Dense(&tags),
        app: &app,
    };
    let bucket = Bucket::fitting(app.len(), |b| b.group_app(3)).unwrap();
    assert_eq!(bucket, Bucket::B1);
    let mut rec3 = vec![0u8; bucket.group_record()];
    seal_content(
        &plain,
        &record_key,
        [0x0b; 12],
        &GROUP_ID,
        1,
        slot_index,
        bucket,
        &mut rec3,
    )
    .unwrap();
    let parsed = GroupQueueRecord::parse(&rec3, bucket).unwrap();
    let mut buf = vec![0u8; bucket.content_plain()];
    let len =
        umbra_wire::group::record::open_content(&parsed, &record_key, &GROUP_ID, &mut buf).unwrap();
    let back = ContentPlain::parse(&buf[..len], |_| Some(3)).unwrap();
    // WIR-467: the named receiver rejects a changed tag and an unknown sender.
    let key_1 = members[1]
        .pair_key(&members[0].pair_public(), &GROUP_ID)
        .unwrap();
    let tag_1 = back.tags.tag_for(1, 1).unwrap();
    key_1.verify_record_tag(&fields, &tag_1).unwrap();
    let mut changed = tag_1;
    changed[0] ^= 1;
    assert!(key_1.verify_record_tag(&fields, &changed).is_err());
    let unknown = RecordTag {
        sender_index: 7,
        ..fields
    };
    assert!(key_1.verify_record_tag(&unknown, &tag_1).is_err());

    // Dense at 500 members with a 350-byte text, in B2.
    let tags500 = vec![0u8; 500 * 12];
    let plain500 = ContentPlain {
        tags: Tags::Dense(&tags500),
        ..plain.clone()
    };
    let bucket500 = Bucket::fitting(app.len(), |b| b.group_app(500)).unwrap();
    assert_eq!(bucket500, Bucket::B2);
    let mut rec500 = vec![0u8; bucket500.group_record()];
    seal_content(
        &plain500,
        &record_key,
        [0x0c; 12],
        &GROUP_ID,
        1,
        slot_index,
        bucket500,
        &mut rec500,
    )
    .unwrap();

    // Sparse presence.
    let mut presence_app = vec![0u8; 30 + 3];
    let control = GroupControl {
        control_type: ControlType::Presence,
        payload: &PRESENCE,
    };
    let mut control_bytes = [0u8; 3];
    control.encode(&mut control_bytes).unwrap();
    AppMessage {
        kind: AppKind::GroupControl,
        msg_id: [0x0d; 16],
        sent_at: 0,
        body: &control_bytes,
    }
    .encode(&mut presence_app)
    .unwrap();
    let sparse = ContentPlain {
        sender_index: 2,
        counter: 1,
        roster_epoch: 1,
        tags: Tags::Sparse(vec![(0, [0x0e; 12])]),
        app: &presence_app,
    };
    let mut sparse_plain = vec![0u8; Bucket::B0.content_plain()];
    sparse.encode(Bucket::B0, &mut sparse_plain).unwrap();

    // Inline epoch-key record at 3 members, member 0 an owner.
    let epoch_secret = EpochSecret::new(Secret::new([0x6c; 32]));
    let mut slots = Vec::new();
    let mut sealed = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let own = if index == 0 { 2 } else { 0 };
        let tag = members[1]
            .pair_key(&member.pair_public(), &GROUP_ID)
            .map(|k| {
                k.epoch_tag(&umbra_crypto::group::pair::EpochTag {
                    group_id: &GROUP_ID,
                    epoch: 2,
                    start_slot: 497_010,
                    roster_epoch: 1,
                    epoch_secret: epoch_secret.expose(),
                })
            })
            .unwrap_or([0; 12]);
        let payload = SlotPayload {
            rotator: 1,
            epoch_secret: Secret::new(*epoch_secret.expose().expose()),
            tag,
            own_sks: (0..own).map(|i| Secret::new([0x70 + i; 32])).collect(),
        };
        let mut payload_bytes = vec![0u8; payload.len()];
        payload.encode(&mut payload_bytes).unwrap();
        let (ct, ss) = kem::encapsulate_deterministic(
            member.kem().public(),
            Secret::new([0x11 + index as u8; 32]),
            Secret::new([0x22 + index as u8; 32]),
        );
        let mut s = vec![0u8; slot::sealed_len(payload_bytes.len())];
        slot::seal_with(&ct, &ss, &GROUP_ID, 2, index as u16, &payload_bytes, &mut s).unwrap();
        sealed.push(s);
    }
    for (index, s) in sealed.iter().enumerate() {
        slots.push(KemSlot {
            index: index as u16,
            sealed: s,
        });
    }
    let body = EpochKeyBody {
        roster_epoch: 1,
        slot_count: 3,
        carrier: Carrier::Inline(slots),
    };
    let ek_bucket = Bucket::fitting(7 + 1_249 + 2 * 1_185, |b| Some(b.group_body())).unwrap();
    assert_eq!(ek_bucket, Bucket::B2);
    let mut ek_body = vec![0u8; ek_bucket.group_body()];
    body.encode(ek_bucket, &mut ek_body).unwrap();
    let ek_record = GroupQueueRecord {
        kind: umbra_wire::group::record::RecordKind::EpochKey,
        epoch: 2,
        slot: 497_010,
        nonce: [0; 12],
        body: &ek_body,
    };
    let mut ek_bytes = vec![0u8; ek_bucket.group_record()];
    ek_record.encode(ek_bucket, &mut ek_bytes).unwrap();
    let roles = |i: u16| match i {
        0 => Some(2),
        1 | 2 => Some(0),
        _ => None,
    };
    let parsed_body = EpochKeyBody::parse(&ek_body, roles).unwrap();
    if let Carrier::Inline(list) = &parsed_body.carrier {
        let mut opened = vec![0u8; 47];
        slot::open(
            members[2].kem(),
            &GROUP_ID,
            2,
            2,
            list[2].sealed,
            &mut opened,
        )
        .unwrap();
        let payload = SlotPayload::parse(&opened).unwrap();
        assert_eq!(
            payload.epoch_secret.expose(),
            epoch_secret.expose().expose()
        );
    }
    // The segment of the slot at rank 299 at 27 slots per chunk is segment 11.
    let sizes = vec![1_185usize; 500];
    let per_chunk = EpochKeyBody::slots_per_chunk(&sizes, 32_634).unwrap();
    assert_eq!(per_chunk, 27);
    assert_eq!(299 / usize::from(per_chunk), 11);

    // Group commands: GKEY, GSEQ, and a GPOST header.
    let gkey = GkeyPayload {
        read_pk: [0x7a; 32],
        write_pk: [0x7b; 32],
        own_pk: [0x7d; 32],
    };
    let mut gkey_bytes = [0u8; 96];
    gkey.encode(&mut gkey_bytes).unwrap();
    let gseq = GseqPayload {
        corr_id: [0x7c; 16],
        seq: 42,
    };
    let mut gseq_bytes = [0u8; 20];
    gseq.encode(&mut gseq_bytes).unwrap();
    let gpost = Command {
        cmd: Cmd::Group(umbra_wire::group::GroupCmd::Gpost),
        corr_id: [0x7c; 16],
        queue_id: [0x7d; 32],
        auth: [0x7e; 32],
        payload: &rec3,
    };
    let mut gpost_bytes = vec![0u8; gpost.len()];
    gpost.encode(&mut gpost_bytes).unwrap();
    assert!(Command::parse(&gpost_bytes, Bucket::B1).is_ok());
    assert!(Command::parse(&gpost_bytes, Bucket::B2).is_err());

    json!({
        "note": "The relay-side grace rules of WIR-468 and WIR-469 are behavior, not encoding, and the relay crate tests them.",
        "member_seeds": (0..3u8).map(|i| hex(&[0x61 + i; 32])).collect::<Vec<_>>(),
        "k_e": hex(&[0x6b; 32]), "t_e": 497_000, "slot": slot_index,
        "dense_3_members_b1": { "bucket": bucket.cell_len(), "app_len": app.len(), "tags": hex(&tags), "record": hex(&rec3) },
        "dense_500_members_b2": { "bucket": bucket500.cell_len(), "record_head": hex(&rec500[..64]), "record_len": rec500.len() },
        "sparse_presence_plain": hex(&sparse_plain),
        "epoch_key_inline_3": { "bucket": ek_bucket.cell_len(), "k_e": hex(&[0x6c; 32]), "record": hex(&ek_bytes) },
        "chunked_rank_299": { "slots_per_chunk": per_chunk, "segment": 11 },
        "gkey": hex(&gkey_bytes), "gseq": hex(&gseq_bytes), "gpost_header": hex(&gpost_bytes[..84]),
    })
}

fn group_controls() -> Value {
    let chain = Chain {
        group_id: GROUP_ID,
        epoch_index: 3,
        previous_epoch_hash: [0x80; 32],
    };
    let keys = JoinKeys {
        pair_pk: [0x81; 32],
        roster_pk_hash: [0x82; 32],
        kem_pk: &[0x83; 1_216],
    };
    let granter = SigningKey::from_seed(Secret::new([0x84; 32]));
    let grantee = SigningKey::from_seed(Secret::new([0x85; 32]));
    let grantee_pk = grantee.verifying_key().to_bytes();
    let mut out = serde_json::Map::new();
    let mut buf = vec![0u8; 8_000];

    let n = JoinRecord {
        group_id: GROUP_ID,
        keys: keys.clone(),
    }
    .encode(&mut buf)
    .unwrap();
    out.insert("join".into(), json!(hex(&buf[..n])));

    let n = PlainEpoch {
        chain,
        op: PlainOp::Add {
            index: 4,
            keys: keys.clone(),
        },
    }
    .encode(&mut buf)
    .unwrap();
    out.insert("plain_add".into(), json!(hex(&buf[..n])));
    for (name, op) in [
        ("plain_remove", PlainOp::Remove { index: 4 }),
        ("plain_self_removal", PlainOp::SelfRemoval),
    ] {
        let epoch = PlainEpoch { chain, op };
        let n = epoch.encode(&mut buf).unwrap();
        assert_eq!(PlainEpoch::parse(&buf[..n]).unwrap(), epoch);
        out.insert(name.into(), json!(hex(&buf[..n])));
    }

    let granter_pk = granter.verifying_key().to_bytes();
    let mut grant = GrantingEpoch {
        chain,
        granter_index: 0,
        grantee_index: 4,
        grantee_roster_pk_hash: sha3_256(&[&grantee_pk]),
        role: Role::Admin,
        granter_roster_pk: &granter_pk,
        sig: &[0; SIGNATURE_LEN],
    };
    let sig = granter
        .sign(&grant.preimage(), &mut Rng(1))
        .unwrap()
        .to_bytes();
    grant.sig = &sig;
    let n = grant.encode(&mut buf).unwrap();
    GrantingEpoch::parse(&buf[..n])
        .unwrap()
        .verify(&sha3_256(&[&granter_pk]))
        .unwrap();
    out.insert("granting".into(), json!(hex(&buf[..n])));

    let mut moderation = ModerationEpoch {
        chain,
        actor_index: 0,
        actor_role: Role::Admin,
        actions: vec![ModAction {
            action: 1,
            target: [0x86; 16],
            author_hint: 0xFFFF,
        }],
        actor_roster_pk: &granter_pk,
        sig: &[0; SIGNATURE_LEN],
    };
    let sig = granter
        .sign(&moderation.preimage(), &mut Rng(2))
        .unwrap()
        .to_bytes();
    moderation.sig = &sig;
    let n = moderation.encode(&mut buf).unwrap();
    ModerationEpoch::parse(&buf[..n])
        .unwrap()
        .verify(&sha3_256(&[&granter_pk]))
        .unwrap();
    out.insert("moderation".into(), json!(hex(&buf[..n])));

    out.insert("presence".into(), json!(hex(&PRESENCE)));

    let n = GroupInvitation {
        group_id: GROUP_ID,
        stage: InvitationStage::Offer {
            name: "friends",
            admin_roster_pk: &granter.verifying_key().to_bytes(),
            creator_roster_pk: &granter.verifying_key().to_bytes(),
        },
    }
    .encode(&mut buf)
    .unwrap();
    out.insert("invitation_offer".into(), json!(hex(&buf[..n])));
    let rep = ReplicaRef {
        relay_id: [0x87; 32],
        group_queue_id: [0x88; 32],
        seq_of_add: 12,
    };
    let n = GroupInvitation {
        group_id: GROUP_ID,
        stage: InvitationStage::Admit(Box::new(InvitationAdmit {
            index: 4,
            epoch: 1,
            t_e: 496_900,
            t_join: 497_000,
            slot_key: [0x89; 32],
            read_sk: [0x8d; 32],
            write_sk: [0x8e; 32],
            roster_epoch: 3,
            replicas: [rep, rep],
            descriptor: &[0x8a; 257],
        })),
    }
    .encode(&mut buf)
    .unwrap();
    out.insert("invitation_admit".into(), json!(hex(&buf[..n])));

    let n = SnapshotNotice {
        group_id: GROUP_ID,
        roster_epoch: 3,
        descriptor: &[0x8b; 257],
    }
    .encode(&mut buf)
    .unwrap();
    out.insert("snapshot_notice".into(), json!(hex(&buf[..n])));

    let old = SigningKey::from_seed(Secret::new([0x8c; 32]));
    let old_pk = old.verifying_key().to_bytes();
    let mut rekey = RekeyRecord {
        chain,
        old_index: 2,
        old_roster_pk: &old_pk,
        new_index: 5,
        new_keys: keys,
        sig: &[0; SIGNATURE_LEN],
    };
    let sig = old.sign(&rekey.preimage(), &mut Rng(3)).unwrap().to_bytes();
    rekey.sig = &sig;
    let n = rekey.encode(&mut buf).unwrap();
    RekeyRecord::parse(&buf[..n])
        .unwrap()
        .verify(&sha3_256(&[&old_pk]))
        .unwrap();
    let mut changed = buf[..n].to_vec();
    changed[69] ^= 1;
    assert!(RekeyRecord::parse(&changed)
        .unwrap()
        .verify(&sha3_256(&[&old_pk]))
        .is_err());
    out.insert("rekey".into(), json!(hex(&buf[..n])));

    // WIR-471: a snapshot at 3 members in one segment, and the segment
    // count of a snapshot at GROUP_MAX.
    let segment = usize::try_from(CHUNK_SIZE).unwrap() - 16;
    let kem_pks: Vec<[u8; 1_216]> = (0..3u8).map(|i| [0xc0 + i; 1_216]).collect();
    let entry = |i: u16, role: Role, kem_pk: &[u8]| GroupMemberEntry {
        index: i,
        role,
        pair_pk: [0xc4 + i as u8; 32],
        roster_pk_hash: [0xc8 + i as u8; 32],
        kem_pk_hash: sha3_256(&[kem_pk]),
    };
    let snapshot = RosterSnapshot {
        group_id: GROUP_ID,
        roster_epoch: 3,
        chain_hash: [0xcc; 32],
        entries: vec![
            entry(0, Role::Owner, &kem_pks[0]),
            entry(1, Role::Admin, &kem_pks[1]),
            entry(2, Role::Member, &kem_pks[2]),
        ],
        keys: (0..3u16)
            .map(|i| MemberKemKey {
                index: i,
                kem_pk: &kem_pks[usize::from(i)],
            })
            .collect(),
        path: &[],
    };
    let mut snapshot_bytes = vec![0u8; snapshot.len()];
    let n = snapshot.encode(&mut snapshot_bytes).unwrap();
    assert_eq!(n, 4_028);
    assert!(n <= segment);
    assert_eq!(RosterSnapshot::parse(&snapshot_bytes).unwrap(), snapshot);
    out.insert("roster_snapshot_3".into(), json!(hex(&snapshot_bytes)));
    let full = RosterSnapshot {
        entries: vec![entry(0, Role::Member, &kem_pks[0]); 500],
        keys: vec![
            MemberKemKey {
                index: 0,
                kem_pk: &kem_pks[0],
            };
            500
        ],
        ..snapshot.clone()
    };
    assert_eq!(full.len(), 658_577);
    assert_eq!(full.len().div_ceil(segment), 21);
    out.insert(
        "roster_snapshot_group_max".into(),
        json!({ "members": 500, "len": full.len(), "segment_size": segment, "segments": 21 }),
    );
    // WIR-480.
    for b in [0x00u8, 0x01, 0x0A] {
        assert!(ControlType::from_byte(b).is_err());
    }
    Value::Object(out)
}

fn app_bodies() -> Value {
    let mut buf = vec![0u8; 2_000];
    let mut out = serde_json::Map::new();
    let mut put = |name: &str, n: usize, buf: &[u8]| {
        out.insert(name.into(), json!(hex(&buf[..n])));
    };

    let rich = RichRecord {
        reply_target: [0x90; 16],
        thread_root: [0x91; 16],
        forward_depth: 1,
        mentions: (0..16u8).map(|i| [i; 16]).collect(),
        inner_kind: AppKind::Text,
        inner_body: b"reply",
    };
    let n = rich.encode(Channel::Group, &mut buf).unwrap();
    put("rich_thread_16_mentions", n, &buf);

    let q = "q".repeat(200);
    let o = "o".repeat(100);
    let poll = Poll {
        multiple: true,
        hidden: false,
        open_seconds: 86_400,
        question: &q,
        options: vec![&o; 12],
    };
    let n = poll.encode(&mut buf).unwrap();
    assert_eq!(n, 1_420);
    put("poll_max", n, &buf);
    let n = PollVote {
        target: [0x92; 16],
        choices: (0..12).collect(),
    }
    .encode(&poll, &mut buf)
    .unwrap();
    assert_eq!(n, 30);
    put("vote_12", n, &buf);

    let n = ContactShare {
        share_type: ShareType::Grant,
        name: "Carol",
        body: b"invitation",
    }
    .encode(&mut buf)
    .unwrap();
    put("share_grant", n, &buf);

    let n = ReactionBody {
        target: [0x93; 16],
        action: ReactionAction::Add,
        emoji: "👍🏽",
    }
    .encode(&mut buf)
    .unwrap();
    put("reaction", n, &buf);
    let n = TypingState::Stopped.encode(&mut buf).unwrap();
    put("typing_stopped", n, &buf);
    let n = ReceiptBody {
        targets: (0..9u8).map(|i| [0x94 + i; 16]).collect(),
    }
    .encode(&mut buf)
    .unwrap();
    put("receipt_9", n, &buf);
    let n = encode_timer(TIMER_VALUES[8], &mut buf).unwrap();
    put("timer_90d", n, &buf);

    let n = DigestBody {
        source: DigestSource::ConsensusRoot,
        epoch: 77,
        digest: [0x95; 32],
    }
    .encode(&mut buf)
    .unwrap();
    put("digest", n, &buf);
    let request = KeyRequest {
        scope: KeyScope::GroupEpoch,
        id: GROUP_ID,
        epoch: 2,
        index: 0,
    };
    let n = request.encode(&mut buf).unwrap();
    put("key_request_group", n, &buf);
    let n = KeySupply {
        request,
        status: SupplyStatus::Posted,
        body: b"",
    }
    .encode(&mut buf)
    .unwrap();
    put("key_supply_posted", n, &buf);

    let n = DeviceSetBody::Control {
        control_type: DevType::SyncAck,
        payload: &1_000u64.to_be_bytes(),
    }
    .encode(&mut buf)
    .unwrap();
    put("sync_ack", n, &buf);

    let desc = FileDescriptor {
        level: Level::Data,
        file_key: Secret::new([0x96; 32]),
        file_nonce: [0x97; 24],
        commit: [0x98; 32],
        digest: [0x99; 32],
        media_seconds: 0,
        padded_size: CHUNK_SIZE * 13,
        mime_class: 1,
        pixel_w: 0,
        pixel_h: 0,
        refs: (0..13u8)
            .map(|i| ChunkRef {
                relay_id: [i; 32],
                chunk_id: [0x10 + i; 32],
                cred_pk: [0x20 + i; 32],
                replicas: [[0x30 + i; 12], [0x40 + i; 12]],
            })
            .collect(),
    };
    let n = desc.encode(&mut buf).unwrap();
    // WIR-134: 13 refs are the most an attachment record holds in B1 with
    // no braid frame, and 14 do not fit.
    assert!(n + 30 <= Bucket::B1.app_no_frame());
    assert!(n + 120 + 30 > Bucket::B1.app_no_frame());
    put("descriptor_13_refs", n, &buf);

    let n = NewPayload {
        qr_auth_pk: [0x9a; 32],
        qs_auth_pk: [0x9b; 32],
        admission: Admission::NONE,
    }
    .encode(&mut buf)
    .unwrap();
    put("new_payload", n, &buf);
    let n = IdsPayload {
        recipient_id: [0x9c; 32],
        sender_id: [0x9d; 32],
        relay_session_pk: [0x9e; 32],
    }
    .encode(&mut buf)
    .unwrap();
    put("ids_payload", n, &buf);
    let n = NackPayload {
        corr_id: [0x9f; 16],
        reason: Reason::Admission,
    }
    .encode(&mut buf)
    .unwrap();
    put("nack", n, &buf);

    let msg = AppMessage {
        kind: AppKind::Text,
        msg_id: [0xa0; 16],
        sent_at: 1_700_000_000_000,
        body: "hello".as_bytes(),
    };
    let n = msg.encode(&mut buf).unwrap();
    put("app_text", n, &buf);
    // WIR-304 and WIR-096.
    let mut bad = buf[..n].to_vec();
    bad[30] = 0xFF;
    assert!(AppMessage::parse(&bad, Channel::Pairwise).is_err());

    // WIR-203: the three cases beside the record at MENTION_MAX.
    let plain = RichRecord {
        reply_target: [0; 16],
        thread_root: [0; 16],
        forward_depth: 0,
        mentions: Vec::new(),
        inner_kind: AppKind::Text,
        inner_body: b"text",
    };
    let reply = RichRecord {
        reply_target: [0x90; 16],
        ..plain.clone()
    };
    let threaded = RichRecord {
        thread_root: [0x91; 16],
        ..reply.clone()
    };
    for (name, record, channel) in [
        ("rich_plain", &plain, Channel::Pairwise),
        ("rich_reply", &reply, Channel::Pairwise),
        ("rich_reply_thread", &threaded, Channel::Group),
    ] {
        let n = record.encode(channel, &mut buf).unwrap();
        assert_eq!(&RichRecord::parse(&buf[..n], channel).unwrap(), record);
        put(name, n, &buf);
    }
    // An inner text that is not UTF-8 is malformed inside a wrapper too.
    let n = plain.encode(Channel::Pairwise, &mut buf).unwrap();
    buf[n - 1] = 0xFF;
    assert!(RichRecord::parse(&buf[..n], Channel::Pairwise).is_err());

    // WIR-205: a poll at 2 options.
    let small = Poll {
        multiple: false,
        hidden: true,
        open_seconds: 0,
        question: "?",
        options: vec!["a", "b"],
    };
    let n = small.encode(&mut buf).unwrap();
    assert_eq!(Poll::parse(&buf[..n]).unwrap(), small);
    put("poll_2_options", n, &buf);

    // WIR-207: the request and the offer.
    for (name, share_type, body) in [
        ("share_request", ShareType::Request, &b""[..]),
        ("share_offer", ShareType::Offer, &b"invitation"[..]),
    ] {
        let share = ContactShare {
            share_type,
            name: "Carol",
            body,
        };
        let n = share.encode(&mut buf).unwrap();
        assert_eq!(ContactShare::parse(&buf[..n]).unwrap(), share);
        put(name, n, &buf);
    }

    // WIR-302: a reaction at 1 byte and at REACTION_MAX_BYTES, the other
    // typing state, and a receipt at 1 target.
    let emoji64 = "👍🏽".repeat(8);
    assert_eq!(emoji64.len(), 64);
    for (name, emoji) in [
        ("reaction_1_byte", "x"),
        ("reaction_64_bytes", emoji64.as_str()),
    ] {
        let reaction = ReactionBody {
            target: [0x93; 16],
            action: ReactionAction::Remove,
            emoji,
        };
        let n = reaction.encode(&mut buf).unwrap();
        assert_eq!(ReactionBody::parse(&buf[..n]).unwrap(), reaction);
        put(name, n, &buf);
    }
    let n = TypingState::Started.encode(&mut buf).unwrap();
    put("typing_started", n, &buf);
    let n = ReceiptBody {
        targets: vec![[0x94; 16]],
    }
    .encode(&mut buf)
    .unwrap();
    put("receipt_1", n, &buf);

    // WIR-209: each value of the set but the last, which `timer_90d` holds.
    for (name, seconds) in [
        ("timer_off", 0u32),
        ("timer_30s", 30),
        ("timer_5m", 300),
        ("timer_1h", 3_600),
        ("timer_8h", 28_800),
        ("timer_1d", 86_400),
        ("timer_7d", 604_800),
        ("timer_28d", 2_419_200),
    ] {
        assert!(TIMER_VALUES.contains(&seconds));
        let n = encode_timer(seconds, &mut buf).unwrap();
        assert_eq!(parse_timer(&buf[..n]).unwrap(), seconds);
        put(name, n, &buf);
    }
    assert_eq!(TIMER_VALUES.len(), 9);

    // WIR-156: the two other sources.
    for (name, source) in [
        ("digest_tree_head", DigestSource::TreeHead),
        ("digest_release_log", DigestSource::ReleaseLog),
    ] {
        let digest = DigestBody {
            source,
            epoch: 77,
            digest: [0x95; 32],
        };
        let n = digest.encode(&mut buf).unwrap();
        assert_eq!(DigestBody::parse(&buf[..n]).unwrap(), digest);
        put(name, n, &buf);
    }

    // WIR-342: a request and a supply in each scope, and a supply of each
    // status.
    let session = KeyRequest {
        scope: KeyScope::Session,
        id: [0xa1; 32],
        epoch: 4,
        index: 65_535,
    };
    let roster = KeyRequest {
        scope: KeyScope::RosterSnapshot,
        id: GROUP_ID,
        epoch: 3,
        index: 0,
    };
    for (name, request) in [
        ("key_request_session", session),
        ("key_request_roster", roster),
    ] {
        let n = request.encode(&mut buf).unwrap();
        assert_eq!(KeyRequest::parse(&buf[..n]).unwrap(), request);
        put(name, n, &buf);
    }
    for (name, request, status) in [
        ("key_supply_session_resent", session, SupplyStatus::Resent),
        (
            "key_supply_session_not_held",
            session,
            SupplyStatus::NotHeld,
        ),
        ("key_supply_roster_posted", roster, SupplyStatus::Posted),
    ] {
        let supply = KeySupply {
            request,
            status,
            body: b"",
        };
        let n = supply.encode(&mut buf).unwrap();
        assert_eq!(KeySupply::parse(&buf[..n]).unwrap(), supply);
        put(name, n, &buf);
    }
    // A supply with a body is malformed (WIR-332).
    buf[44] = 1;
    assert!(KeySupply::parse(&buf[..46]).is_err());

    // The trailer of an AttachmentBody: a name and a caption, with no
    // preview.
    let one_ref = FileDescriptor {
        level: Level::Data,
        file_key: Secret::new([0x96; 32]),
        file_nonce: [0x97; 24],
        commit: [0x98; 32],
        digest: [0x99; 32],
        media_seconds: 0,
        padded_size: CHUNK_SIZE,
        mime_class: class::DOC,
        pixel_w: 0,
        pixel_h: 0,
        refs: vec![ChunkRef {
            relay_id: [0xa2; 32],
            chunk_id: [0xa3; 32],
            cred_pk: [0xa4; 32],
            replicas: [[0xa5; 12], [0xa6; 12]],
        }],
    };
    let attachment = AttachmentBody {
        descriptor: one_ref,
        name: Some("Report 2026.pdf".into()),
        preview: None,
        caption: Some("The summit at six"),
    };
    let n = attachment.encode(&mut buf).unwrap();
    assert_eq!(n, 257 + 3 + 15 + 2 + 17);
    let back = AttachmentBody::parse(&buf[..n]).unwrap();
    assert_eq!(back.name, attachment.name);
    assert_eq!(back.caption, attachment.caption);
    put("attachment_name_caption", n, &buf);
    // WIR-532: a trailer that carries nothing is malformed. A name with a
    // bidirectional format character reads with none, and no sender writes
    // one.
    let mut bare = buf[..257].to_vec();
    assert!(AttachmentBody::parse(&bare).is_ok());
    bare.extend_from_slice(&[0, 0, 0]);
    assert!(AttachmentBody::parse(&bare).is_err());
    let mut turned = buf[..257].to_vec();
    turned.push(7);
    turned.extend_from_slice("a\u{202E}b.c".as_bytes());
    turned.extend_from_slice(&[0, 0]);
    let read = AttachmentBody::parse(&turned).unwrap();
    assert_eq!(read.name.as_deref(), Some("ab.c"));
    let written = AttachmentBody {
        descriptor: read.descriptor,
        name: Some("a\u{202E}b.c".into()),
        preview: None,
        caption: None,
    };
    assert!(written.encode(&mut [0u8; 300]).is_err());

    let share = RecoveryShare {
        set_id: [0xa7; 16],
        threshold: 3,
        count: 5,
        share: [2; 17],
    };
    let bytes = share.encode().unwrap();
    assert_eq!(RecoveryShare::parse(&bytes).unwrap(), share);
    put("recovery_share", bytes.len(), &bytes);

    let notice = KeyChangeNotice {
        new_x25519_pk: [0xa8; 32],
        new_mlkem_pk: &[0xa9; 1_184],
    };
    let n = notice.encode(&mut buf).unwrap();
    assert_eq!(n, 1_217);
    assert_eq!(KeyChangeNotice::parse(&buf[..n]).unwrap(), notice);
    put("key_change", n, &buf);

    // The payloads of an IPUT and of an IBLOB at B0, with the zero fill.
    let iput = iput_payload(&[0xaa; 24], b"invitation", Bucket::B0).unwrap();
    assert_eq!(iput.len(), Bucket::B0.l6_record());
    assert_eq!(iput_parse(&iput).unwrap(), ([0xaa; 24], &b"invitation"[..]));
    put("iput_payload_b0", iput.len(), &iput);
    let iblob = iblob_payload(b"invitation", Bucket::B0).unwrap();
    assert_eq!(iblob_parse(&iblob).unwrap(), b"invitation");
    put("iblob_payload_b0", iblob.len(), &iblob);
    let mut bad = iblob.clone();
    *bad.last_mut().unwrap() = 1;
    assert!(iblob_parse(&bad).is_err());
    Value::Object(out)
}

fn directory_envelopes() -> Value {
    // Part 9 §9.10: one request, and one response at each size. The fill
    // is zero bytes, thus a vector holds the head and the length.
    let request = directory::encode_request(directory::Kind::Lookup, &[0xb0; 32]).unwrap();
    assert_eq!(request.len(), directory::DIR_REQUEST_LEN);
    assert_eq!(
        directory::parse_request(&request).unwrap(),
        (directory::Kind::Lookup, &[0xb0u8; 32][..])
    );
    assert!(request[36..].iter().all(|b| *b == 0));
    let mut responses = Vec::new();
    for (body_len, size) in [(32usize, 4_096usize), (4_091, 32_768), (32_763, 98_304)] {
        let body = vec![0xb1u8; body_len];
        let response = directory::encode_response(directory::Status::Done, &body).unwrap();
        assert_eq!(response.len(), size);
        assert_eq!(directory::parse_response(&response).unwrap().1, &body[..]);
        // The same body in a larger size is not the response of that body.
        if let Some(larger) = directory::DIR_RESPONSE_SIZES
            .into_iter()
            .find(|larger| *larger > size)
        {
            let mut wide = response.clone();
            wide.resize(larger, 0);
            assert!(directory::parse_response(&wide).is_err());
        }
        responses.push(json!({
            "body_len": body_len, "len": size, "head": hex(&response[..8]),
        }));
    }
    json!({
        "request": { "len": request.len(), "head": hex(&request[..36]) },
        "responses": responses,
    })
}

fn build() -> Value {
    json!({
        "note": "Wire vectors of Part 6 §6.8. Self-generated; not independently confirmed.",
        "framing": framing(),
        "ratchet_records": ratchet_records(),
        "queue_records": queue_records(),
        "edit_and_delete": edit_and_delete(),
        "group_records": group_records(),
        "group_controls": group_controls(),
        "app_bodies": app_bodies(),
        "directory": directory_envelopes(),
    })
}

#[test]
#[ignore = "writes the vector file; run by hand"]
fn generate() {
    fs::write(path(), serde_json::to_string_pretty(&build()).unwrap()).unwrap();
}

#[test]
fn wire_vectors_hold() {
    let stored: Value = serde_json::from_str(&fs::read_to_string(path()).unwrap()).unwrap();
    assert_eq!(stored, build());
}
