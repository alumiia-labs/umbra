//! The file descriptor of Part 12 §12.3: what a receiver needs to fetch
//! and open one object on the chunk path.

use alloc::vec::Vec;

use umbra_crypto::secret::Secret;

use crate::{
    codec::{Reader, Writer},
    Error,
};

/// The fixed part.
pub const FIXED: usize = 137;
/// One `ChunkRef`.
pub const CHUNK_REF_LEN: usize = 120;
/// `CHUNK_SIZE`, which `padded_size` must divide by (`ATT-068`).
pub const CHUNK_SIZE: u32 = 32_650;

/// The level of the refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Level {
    /// The refs address data chunks.
    Data = 0x00,
    /// The refs address manifest chunks (§12.3.4).
    Manifest = 0x01,
}

/// One chunk and its two replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    /// The relay that holds the chunk.
    pub relay_id: [u8; 32],
    /// The chunk.
    pub chunk_id: [u8; 32],
    /// The read credential.
    pub cred_pk: [u8; 32],
    /// The two replica hints of §12.3.2.
    pub replicas: [[u8; 12]; 2],
}

/// A file descriptor. It holds the file key, thus it has no `Debug`.
pub struct FileDescriptor {
    /// The level.
    pub level: Level,
    /// The XChaCha20-Poly1305 key.
    pub file_key: Secret<32>,
    /// The nonce.
    pub file_nonce: [u8; 24],
    /// The key commitment of §12.3.1.
    pub commit: [u8; 32],
    /// SHA3-256 of the plaintext.
    pub digest: [u8; 32],
    /// The duration of an audio or a video object, else 0.
    pub media_seconds: u16,
    /// The data chunk count times `CHUNK_SIZE`.
    pub padded_size: u32,
    /// The media class.
    pub mime_class: u8,
    /// The width of an image or a video, else 0.
    pub pixel_w: u16,
    /// The height of an image or a video, else 0.
    pub pixel_h: u16,
    /// The refs.
    pub refs: Vec<ChunkRef>,
}

impl FileDescriptor {
    /// The encoded length.
    pub fn len(&self) -> usize {
        FIXED.saturating_add(self.refs.len().saturating_mul(CHUNK_REF_LEN))
    }

    /// Whether the descriptor names no chunk. Clippy asks for this beside
    /// `len`.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    /// Writes the descriptor.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        if !self.padded_size.is_multiple_of(CHUNK_SIZE) {
            return Err(Error::Malformed);
        }
        let mut w = Writer::new(out);
        w.u8(0x01)?;
        w.u8(self.level as u8)?;
        w.put(self.file_key.expose())?;
        w.put(&self.file_nonce)?;
        w.put(&self.commit)?;
        w.put(&self.digest)?;
        w.u16(self.media_seconds)?;
        w.u32(u32::try_from(self.refs.len()).map_err(|_| Error::Malformed)?)?;
        w.u32(self.padded_size)?;
        w.u8(self.mime_class)?;
        w.u16(self.pixel_w)?;
        w.u16(self.pixel_h)?;
        for r in &self.refs {
            w.put(&r.relay_id)?;
            w.put(&r.chunk_id)?;
            w.put(&r.cred_pk)?;
            w.put(&r.replicas[0])?;
            w.put(&r.replicas[1])?;
        }
        Ok(w.position())
    }

    /// Reads a descriptor.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 0x01 {
            return Err(Error::Malformed);
        }
        let level = match r.u8()? {
            0x00 => Level::Data,
            0x01 => Level::Manifest,
            _ => return Err(Error::Malformed),
        };
        let file_key = Secret::new(r.array()?);
        let file_nonce = r.array()?;
        let commit = r.array()?;
        let digest = r.array()?;
        let media_seconds = r.u16()?;
        let ref_count = r.u32()?;
        let padded_size = r.u32()?;
        if !padded_size.is_multiple_of(CHUNK_SIZE) {
            return Err(Error::Malformed);
        }
        let mime_class = r.u8()?;
        let pixel_w = r.u16()?;
        let pixel_h = r.u16()?;
        // The remaining length bounds the count before any allocation.
        let ref_count = usize::try_from(ref_count).map_err(|_| Error::Malformed)?;
        if ref_count.checked_mul(CHUNK_REF_LEN) != Some(r.remaining()) {
            return Err(Error::Malformed);
        }
        let mut refs = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            refs.push(ChunkRef {
                relay_id: r.array()?,
                chunk_id: r.array()?,
                cred_pk: r.array()?,
                replicas: [r.array()?, r.array()?],
            });
        }
        r.finish()?;
        Ok(FileDescriptor {
            level,
            file_key,
            file_nonce,
            commit,
            digest,
            media_seconds,
            padded_size,
            mime_class,
            pixel_w,
            pixel_h,
            refs,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn a_descriptor_round_trips_at_its_fixed_lengths() {
        let one = ChunkRef {
            relay_id: [1; 32],
            chunk_id: [2; 32],
            cred_pk: [3; 32],
            replicas: [[4; 12], [5; 12]],
        };
        let desc = FileDescriptor {
            level: Level::Data,
            file_key: Secret::new([6; 32]),
            file_nonce: [7; 24],
            commit: [8; 32],
            digest: [9; 32],
            media_seconds: 0,
            padded_size: CHUNK_SIZE,
            mime_class: 1,
            pixel_w: 640,
            pixel_h: 480,
            refs: vec![one],
        };
        let mut out = vec![0u8; desc.len()];
        assert_eq!(desc.encode(&mut out).unwrap(), 257);
        let back = FileDescriptor::parse(&out).unwrap();
        assert_eq!(back.refs, vec![one]);
        assert_eq!(back.pixel_h, 480);
        assert!(FileDescriptor::parse(&out[..256]).is_err());
        out[131] = 1;
        assert!(FileDescriptor::parse(&out).is_err());
    }
}
