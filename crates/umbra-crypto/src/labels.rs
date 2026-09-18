//! Domain-separation labels of Part 5 §5.11.
//!
//! Each KDF call and each signature carries one of these labels first. A
//! label lives here and nowhere else, thus two call sites cannot drift apart.
//! The list follows the order of the register in the specification.

macro_rules! labels {
    ($($name:ident = $value:literal;)*) => {
        $(
            #[doc = concat!("`", $value, "`")]
            pub const $name: &[u8] = $value.as_bytes();
        )*
        /// Every label, in the order of Part 5 §5.11.
        pub const ALL: &[&[u8]] = &[$($name),*];
    };
}

labels! {
    RNG_HARDEN = "umbra/v1/rng-harden";
    STORAGE = "umbra/v1/storage";
    DEVICE_SET = "umbra/v1/device-set";
    PAIRWISE = "umbra/v1/pairwise";
    PUBLIC_ADDRESS = "umbra/v1/public-address";
    INVITE_BLOB = "umbra/v1/invite-blob";
    PROFILE_BLOB = "umbra/v1/profile-blob";
    KEM_COMBINE = "umbra/v1/kem-combine";
    HANDSHAKE_CK = "umbra/v1/handshake-ck";
    PREKEY_ID = "umbra/v1/prekey-id";
    ONION_HOP = "umbra/v1/onion-hop";
    ONION_HOP_UPDATE = "umbra/v1/onion-hop-update";
    RATCHET_ROOT = "umbra/v1/ratchet-root";
    RATCHET_CHAIN = "umbra/v1/ratchet-chain";
    HEADER_KEY = "umbra/v1/header-key";
    PQ_EPOCH = "umbra/v1/pq-epoch";
    CMD_AUTH = "umbra/v1/cmd-auth";
    QUEUE_E2E = "umbra/v1/queue-e2e";
    NTF = "umbra/v1/ntf";
    BACKUP_HANDLE = "umbra/v1/backup-handle";
    BACKUP_WRITE = "umbra/v1/backup-write";
    DIRECTORY_ROOT = "umbra/v1/directory-root";
    DIRECTORY_KEYSET = "umbra/v1/directory-keyset";
    RELAY_DESCRIPTOR = "umbra/v1/relay-descriptor";
    RELAY_LAYER = "umbra/v1/relay-layer";
    RELAY_FAMILY = "umbra/v1/relay-family";
    RELAYREF = "umbra/v1/relayref";
    LINK_RECEIPT = "umbra/v1/link-receipt";
    MEASURER_CERT = "umbra/v1/measurer-cert";
    DEVICE_ROSTER = "umbra/v1/device-roster";
    DEVICE_CLAIM = "umbra/v1/device-claim";
    GROUP_GRANT = "umbra/v1/group-grant";
    GROUP_MODERATION = "umbra/v1/group-moderation";
    GROUP_SLOT = "umbra/v1/group-slot";
    GROUP_SLOT_NEXT = "umbra/v1/group-slot-next";
    GROUP_RECORD_KEY = "umbra/v1/group-record-key";
    GROUP_RECORD = "umbra/v1/group-record";
    GROUP_READ = "umbra/v1/group-read";
    GROUP_WRITE = "umbra/v1/group-write";
    GROUP_PAIR = "umbra/v1/group-pair";
    GROUP_KEM = "umbra/v1/group-kem";
    GROUP_TAG = "umbra/v1/group-tag";
    GROUP_EPOCH_SLOT = "umbra/v1/group-epoch-slot";
    GROUP_EPOCH_TAG = "umbra/v1/group-epoch-tag";
    GROUP_REKEY = "umbra/v1/group-rekey";
    COMMUNITY_ID = "umbra/v1/community-id";
    COMMUNITY_ROSTER = "umbra/v1/community-roster";
    COMMUNITY_CHAIN = "umbra/v1/community-chain";
    COMMUNITY_CHECKPOINT = "umbra/v1/community-checkpoint";
    COMMUNITY_MODERATION = "umbra/v1/community-moderation";
    OPERATOR_REMOVAL = "umbra/v1/operator-removal";
    COMMUNITY_REPORT = "umbra/v1/community-report";
    MENTION = "umbra/v1/mention";
    HANDLE_RENEW = "umbra/v1/handle-renew";
    FILE_MANIFEST = "umbra/v1/file-manifest";
    FILE_COMMIT = "umbra/v1/file-commit";
    CHUNK_READ = "umbra/v1/chunk-read";
    AVATAR_COLOR = "umbra/v1/avatar-color";
    SESSION_TAG = "umbra/v1/session-tag";
    SESSION_RESUME = "umbra/v1/session-resume";
    COMMUNITY_REPLY = "umbra/v1/community-reply";
    COMMUNITY_PULL = "umbra/v1/community-pull";
    COMMUNITY_META_BLOB = "umbra/v1/community-meta-blob";
    COMMUNITY_METADATA = "umbra/v1/community-metadata";
    DEAD_CHANNEL = "umbra/v1/dead-channel";
    CHUNK_PLACE = "umbra/v1/chunk-place";
    BACKUP_READ = "umbra/v1/backup-read";
    BACKUP_KEY = "umbra/v1/backup-key";
    REPORT_KEY = "umbra/v1/report-key";
    TREE_HEAD = "umbra/v1/tree-head";
    SAS_COMMIT = "umbra/v1/sas-commit";
    SAS = "umbra/v1/sas";
    TABLE_MAC = "umbra/v1/table-mac";
    AT_REST_WRAP = "umbra/v1/at-rest-wrap";
    RECORD_KEY = "umbra/v1/record-key";
    SYNC_SEED = "umbra/v1/sync-seed";
    ADDRESS_INDEX = "umbra/v1/address-index";
    COMMUNITY_CONTACT = "umbra/v1/community-contact";
    COMMUNITY_LISTING = "umbra/v1/community-listing";
    HANDLE_WRITE = "umbra/v1/handle-write";
    HELLO_SEED = "umbra/v1/hello-seed";
    HELLO_VERIFIER = "umbra/v1/hello-verifier";
    MODERATOR_SET = "umbra/v1/moderator-set";
    POW = "umbra/v1/pow";
    POW_CHALLENGE = "umbra/v1/pow-challenge";
    TREE_HEAD_KEYSET = "umbra/v1/tree-head-keyset";
    HELLO = "umbra/v1/hello";
}

/// `umbra/v1/handle-key`
///
/// Part 5 §5.2 derives `HandleKey_{j,r}` under this label, and the register
/// of §5.11 does not list it. The code follows §5.2 until the register does.
pub const HANDLE_KEY: &[u8] = b"umbra/v1/handle-key";

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::ALL;

    #[test]
    fn labels_are_distinct_and_prefixed() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.starts_with(b"umbra/v1/"));
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
