#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::{
    find_prekey, nk,
    xk::{self, Initiator, Invitation, OneTimePrekey, Responder},
    AddressType, NoTrace, VersionRange,
};
use crate::{kem::KeyPair, secret::Secret, test_rng::TestRng, Error};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

struct Parties {
    s_i: KeyPair,
    s_r: KeyPair,
    rng: TestRng,
}

fn parties(seed: &[u8]) -> Parties {
    let mut rng = TestRng::new(seed);
    Parties {
        s_i: KeyPair::generate(&mut rng),
        s_r: KeyPair::generate(&mut rng),
        rng,
    }
}

/// Runs a full XKhfs handshake and returns both sides' keys and payloads.
fn run_xk(
    p: &mut Parties,
    range_i: VersionRange,
    range_r: VersionRange,
) -> Result<(xk::SessionKeys, xk::SessionKeys, [u8; 32]), Error> {
    let prekey = OneTimePrekey::generate(&mut p.rng);
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: p.s_r.x25519_public(),
        s1: &s1,
        range_r,
    };
    let mut f1 = [0u8; 4096];
    let (mut init, n1) = Initiator::flight1(
        &inv,
        range_i,
        AddressType::Pairwise,
        b"app-1",
        &mut p.rng,
        &mut f1,
        &mut NoTrace,
    )?;
    assert_eq!(n1, xk::FLIGHT1_FIXED + 16 + 5 + 16);

    let (_, mode, pid) = Responder::peek(&f1[..n1])?;
    assert_eq!(mode, xk::MODE);
    assert_eq!(find_prekey(&pid, [prekey.id()].into_iter()), Some(0));
    let mut app1 = [0u8; 64];
    let (mut resp, got) = Responder::read_flight1(
        &p.s_r,
        prekey,
        range_r,
        AddressType::Pairwise,
        &f1[..n1],
        &mut app1,
        &mut NoTrace,
    )?;
    assert_eq!(&app1[..got.app_len], b"app-1");

    let mut f2 = [0u8; 4096];
    let n2 = resp.flight2(b"app-two", &mut p.rng, &mut f2, &mut NoTrace)?;
    let mut app2 = [0u8; 64];
    let m = init.read_flight2(&f2[..n2], &mut app2, &mut NoTrace)?;
    assert_eq!(&app2[..m], b"app-two");

    let er = Responder::er_of(&f2[..n2])?;
    let mut f3 = [0u8; 4096];
    let (ki, n3) = init.flight3(&p.s_i, &er, b"", &mut f3, &mut NoTrace)?;
    let mut app3 = [0u8; 64];
    let (kr, s_i, m3) = resp.read_flight3(&f3[..n3], &mut app3, &mut NoTrace)?;
    assert_eq!(m3, 0);
    Ok((ki, kr, s_i))
}

#[test]
fn xk_round_trip_agrees_on_every_key() {
    let mut p = parties(b"xk");
    let (ki, kr, s_i) = run_xk(&mut p, VersionRange::V1, VersionRange::V1).unwrap();
    assert_eq!(ki.rk.expose(), kr.rk.expose());
    assert_eq!(ki.hk_i2r.expose(), kr.hk_i2r.expose());
    assert_eq!(ki.hk_r2i.expose(), kr.hk_r2i.expose());
    assert_ne!(ki.hk_i2r.expose(), ki.hk_r2i.expose());
    assert_eq!(ki.transcript, kr.transcript);
    assert_eq!(s_i, p.s_i.x25519_public());
}

/// A client whose run ends mid-handshake takes each side up again from
/// its stored form, and the keys agree as in one run.
#[test]
fn xk_each_side_continues_from_its_stored_form() {
    let mut p = parties(b"stored");
    let prekey = OneTimePrekey::generate(&mut p.rng);
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: p.s_r.x25519_public(),
        s1: &s1,
        range_r: VersionRange::V1,
    };
    let mut f1 = [0u8; 4096];
    let (init, n1) = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"app-1",
        &mut p.rng,
        &mut f1,
        &mut NoTrace,
    )
    .unwrap();
    let mut init = Initiator::restore(&init.export()).unwrap();
    let (mut resp, _) = Responder::read_flight1(
        &p.s_r,
        prekey,
        VersionRange::V1,
        AddressType::Pairwise,
        &f1[..n1],
        &mut [0u8; 64],
        &mut NoTrace,
    )
    .unwrap();
    // A responder before its flight 2 has no stored form.
    assert!(resp.export().is_err());
    let mut f2 = [0u8; 4096];
    let n2 = resp
        .flight2(b"", &mut p.rng, &mut f2, &mut NoTrace)
        .unwrap();
    let resp = Responder::restore(&resp.export().unwrap()).unwrap();
    init.read_flight2(&f2[..n2], &mut [], &mut NoTrace).unwrap();
    let er = Responder::er_of(&f2[..n2]).unwrap();
    let mut f3 = [0u8; 4096];
    let (ki, n3) = init
        .flight3(&p.s_i, &er, b"", &mut f3, &mut NoTrace)
        .unwrap();
    let (kr, s_i, _) = resp.read_flight3(&f3[..n3], &mut [], &mut NoTrace).unwrap();
    assert_eq!(ki.rk.expose(), kr.rk.expose());
    assert_eq!(ki.transcript, kr.transcript);
    assert_eq!(s_i, p.s_i.x25519_public());
    // A form that a byte of the version changes does not read.
    let mut changed = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"",
        &mut p.rng,
        &mut [0u8; 4096],
        &mut NoTrace,
    )
    .unwrap()
    .0
    .export();
    changed[0] ^= 0xff;
    assert!(Initiator::restore(&changed).is_err());
}

#[test]
fn xk_ranges_that_differ_still_agree_and_a_bad_pair_aborts() {
    let mut p = parties(b"ranges");
    let (ki, kr, _) = run_xk(
        &mut p,
        VersionRange { min: 1, max: 1 },
        VersionRange { min: 1, max: 2 },
    )
    .unwrap();
    assert_eq!(ki.transcript, kr.transcript);
    let err = run_xk(
        &mut p,
        VersionRange { min: 2, max: 2 },
        VersionRange { min: 1, max: 1 },
    );
    assert_eq!(err.err(), Some(Error::Handshake));
}

#[test]
fn xk_a_changed_flight_aborts() {
    let mut p = parties(b"tamper");
    let prekey = OneTimePrekey::generate(&mut p.rng);
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: p.s_r.x25519_public(),
        s1: &s1,
        range_r: VersionRange::V1,
    };
    let mut f1 = [0u8; 4096];
    let (_, n1) = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"x",
        &mut p.rng,
        &mut f1,
        &mut NoTrace,
    )
    .unwrap();
    // a changed mode byte aborts before any hash
    let mut bad = f1;
    bad[2] = 0x02;
    let mut app = [0u8; 64];
    let r = Responder::read_flight1(
        &p.s_r,
        OneTimePrekey::from_seed(Secret::new([1u8; 64])),
        VersionRange::V1,
        AddressType::Pairwise,
        &bad[..n1],
        &mut app,
        &mut NoTrace,
    );
    assert_eq!(r.err(), Some(Error::Handshake));
    // a changed byte of the ML-KEM ciphertext fails the flight tag
    let mut bad = f1;
    bad[3 + 16 + 32 + 1184 + 7] ^= 1;
    let r = Responder::read_flight1(
        &p.s_r,
        prekey,
        VersionRange::V1,
        AddressType::Pairwise,
        &bad[..n1],
        &mut app,
        &mut NoTrace,
    );
    assert_eq!(r.err(), Some(Error::Handshake));
}

#[test]
fn xk_a_wrong_address_type_at_one_side_aborts() {
    let mut p = parties(b"addr");
    let prekey = OneTimePrekey::generate(&mut p.rng);
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: p.s_r.x25519_public(),
        s1: &s1,
        range_r: VersionRange::V1,
    };
    let mut f1 = [0u8; 4096];
    let (_, n1) = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"",
        &mut p.rng,
        &mut f1,
        &mut NoTrace,
    )
    .unwrap();
    let mut app = [0u8; 64];
    let r = Responder::read_flight1(
        &p.s_r,
        prekey,
        VersionRange::V1,
        AddressType::Published,
        &f1[..n1],
        &mut app,
        &mut NoTrace,
    );
    assert_eq!(r.err(), Some(Error::Handshake));
}

#[test]
fn xk_an_all_zero_ephemeral_aborts() {
    let mut p = parties(b"zero");
    let prekey = OneTimePrekey::generate(&mut p.rng);
    let s1 = *prekey.encapsulation_key();
    let inv = Invitation {
        s: p.s_r.x25519_public(),
        s1: &s1,
        range_r: VersionRange::V1,
    };
    let mut f1 = [0u8; 4096];
    let (_, n1) = Initiator::flight1(
        &inv,
        VersionRange::V1,
        AddressType::Pairwise,
        b"",
        &mut p.rng,
        &mut f1,
        &mut NoTrace,
    )
    .unwrap();
    f1[3 + 16..3 + 16 + 32].fill(0);
    let mut app = [0u8; 64];
    let r = Responder::read_flight1(
        &p.s_r,
        prekey,
        VersionRange::V1,
        AddressType::Pairwise,
        &f1[..n1],
        &mut app,
        &mut NoTrace,
    );
    assert_eq!(r.err(), Some(Error::Handshake));
}

#[test]
fn find_prekey_touches_every_entry_and_finds_the_first() {
    let ids = [[1u8; 16], [2u8; 16], [3u8; 16], [2u8; 16]];
    assert_eq!(find_prekey(&[2u8; 16], ids.iter()), Some(1));
    assert_eq!(find_prekey(&[9u8; 16], ids.iter()), None);
    assert_eq!(find_prekey(&[1u8; 16], [].iter()), None);
}

#[test]
fn nk_round_trip_and_tamper() {
    let mut rng = TestRng::new(b"nk");
    let s_sk = StaticSecret::random_from_rng(&mut rng);
    let relay = nk::RelayStatic {
        s: *XPublic::from(&s_sk).as_bytes(),
        relay_id: [7u8; 32],
    };
    let mut f1 = [0u8; nk::FLIGHT1_LEN];
    let client = nk::Client::flight1(&relay, &mut rng, &mut f1, &mut NoTrace).unwrap();
    let hop = nk::Relay::read_flight1(&relay, &s_sk, &f1, &mut NoTrace).unwrap();
    let mut f2 = [0u8; nk::FLIGHT2_LEN];
    let ss_r = hop.flight2(&mut rng, &mut f2, &mut NoTrace).unwrap();
    let ss_c = client.read_flight2(&f2, &mut NoTrace).unwrap();
    assert_eq!(ss_c.expose(), ss_r.expose());

    // a different relay_id at the relay fails the flight tag
    let other = nk::RelayStatic {
        s: relay.s,
        relay_id: [8u8; 32],
    };
    assert_eq!(
        nk::Relay::read_flight1(&other, &s_sk, &f1, &mut NoTrace).err(),
        Some(Error::Handshake)
    );
    // a changed flight 2 fails at the client
    let client = nk::Client::flight1(&relay, &mut rng, &mut f1, &mut NoTrace).unwrap();
    let hop = nk::Relay::read_flight1(&relay, &s_sk, &f1, &mut NoTrace).unwrap();
    let _ = hop.flight2(&mut rng, &mut f2, &mut NoTrace).unwrap();
    f2[40] ^= 1;
    assert_eq!(
        client.read_flight2(&f2, &mut NoTrace).err(),
        Some(Error::Handshake)
    );
}
