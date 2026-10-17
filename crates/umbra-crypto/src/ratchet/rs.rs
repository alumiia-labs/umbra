//! The systematic Reed–Solomon erasure code of Part 5 §5.5.2.
//!
//! The code has `k` data chunks and `r` parity chunks over GF(2¹⁶). It is
//! systematic (`CRY-071`, `CRY-073`): the data chunks travel unchanged and
//! first, and any `k` of the `n` chunks rebuild the data (`CRY-079`). One
//! codeword runs across the chunks at one symbol position (`CRY-072`), thus a
//! lost chunk costs one symbol of each codeword.
//!
//! **The evaluation points.** Part 5 fixes a Vandermonde matrix in
//! systematic form. Rule `CRY-139` names the points: `x_i = g^i` for
//! `i` in `0..n`, with `g` the generator `0x0002`. This code builds the
//! Vandermonde matrix `V[i][j] = x_i^j`, and uses `G = V · V[0..k]⁻¹`. Two
//! implementations that take the same points produce byte-identical chunks
//! (`CRY-075`).

use super::gf16;
use crate::Error;

/// The largest data chunk count of the three widths (32-byte chunks).
pub const MAX_K: usize = 72;
/// The largest parity chunk count (32-byte chunks).
pub const MAX_R: usize = 9;
/// The largest chunk total.
pub const MAX_N: usize = MAX_K + MAX_R;

/// A square matrix over GF(2¹⁶) of at most `MAX_K` rows.
struct Matrix {
    k: usize,
    cells: [u16; MAX_K * MAX_K],
}

impl Matrix {
    fn zero(k: usize) -> Self {
        Self {
            k,
            cells: [0; MAX_K * MAX_K],
        }
    }

    fn at(&self, r: usize, c: usize) -> u16 {
        self.cells.get(r * self.k + c).copied().unwrap_or(0)
    }

    fn set(&mut self, r: usize, c: usize, v: u16) {
        if let Some(cell) = self.cells.get_mut(r * self.k + c) {
            *cell = v;
        }
    }

    /// Gauss–Jordan inversion. A singular matrix gives `Error::Length`, which
    /// cannot occur for distinct evaluation points.
    fn inverse(&self) -> Result<Self, Error> {
        let k = self.k;
        let mut a = Self::zero(k);
        a.cells = self.cells;
        let mut inv = Self::zero(k);
        for i in 0..k {
            inv.set(i, i, 1);
        }

        for col in 0..k {
            let pivot = (col..k).find(|&r| a.at(r, col) != 0).ok_or(Error::Length)?;
            if pivot != col {
                for c in 0..k {
                    let (x, y) = (a.at(col, c), a.at(pivot, c));
                    a.set(col, c, y);
                    a.set(pivot, c, x);
                    let (x, y) = (inv.at(col, c), inv.at(pivot, c));
                    inv.set(col, c, y);
                    inv.set(pivot, c, x);
                }
            }

            let scale = gf16::inv(a.at(col, col));
            for c in 0..k {
                a.set(col, c, gf16::mul(a.at(col, c), scale));
                inv.set(col, c, gf16::mul(inv.at(col, c), scale));
            }

            for r in 0..k {
                if r == col {
                    continue;
                }
                let f = a.at(r, col);
                if f == 0 {
                    continue;
                }
                for c in 0..k {
                    a.set(r, c, gf16::add(a.at(r, c), gf16::mul(f, a.at(col, c))));
                    inv.set(r, c, gf16::add(inv.at(r, c), gf16::mul(f, inv.at(col, c))));
                }
            }
        }
        Ok(inv)
    }
}

/// The parameters of one code: `k` data chunks, `r` parity chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    /// Data chunks.
    pub k: usize,
    /// Parity chunks.
    pub r: usize,
}

impl Code {
    /// Chunks in total.
    pub const fn n(self) -> usize {
        self.k + self.r
    }

    /// Row `i` of the systematic generator matrix: for `i < k` the unit row,
    /// for `i >= k` the parity coefficients. `inv_top` is the inverse of the
    /// top `k` rows of the Vandermonde matrix, computed once per call site.
    fn row(self, inv_top: &Matrix, i: usize, out: &mut [u16]) {
        if i < self.k {
            for (c, cell) in out.iter_mut().enumerate().take(self.k) {
                *cell = u16::from(c == i);
            }
            return;
        }

        // G[i] = V[i] · V_top⁻¹
        let x = gf16::pow(gf16::GENERATOR, i as u32);
        for (c, cell) in out.iter_mut().enumerate().take(self.k) {
            let mut acc = 0u16;
            for j in 0..self.k {
                acc = gf16::add(acc, gf16::mul(gf16::pow(x, j as u32), inv_top.at(j, c)));
            }
            *cell = acc;
        }
    }

    fn vandermonde_top(self) -> Matrix {
        let mut m = Matrix::zero(self.k);
        for i in 0..self.k {
            let x = gf16::pow(gf16::GENERATOR, i as u32);
            for j in 0..self.k {
                m.set(i, j, gf16::pow(x, j as u32));
            }
        }
        m
    }

    /// Writes the `r` parity chunks of `data` into `parity`. `data` holds `k`
    /// chunks of `w` bytes in order; `parity` holds `r` chunks of `w` bytes.
    pub fn encode(self, w: usize, data: &[u8], parity: &mut [u8]) -> Result<(), Error> {
        if !w.is_multiple_of(2) || data.len() != self.k * w || parity.len() != self.r * w {
            return Err(Error::Length);
        }

        let inv_top = self.vandermonde_top().inverse()?;
        let mut coeff = [0u16; MAX_K];

        for p in 0..self.r {
            self.row(&inv_top, self.k + p, &mut coeff);
            for sym in 0..w / 2 {
                let mut acc = 0u16;
                for (m, c) in coeff.iter().enumerate().take(self.k) {
                    acc = gf16::add(acc, gf16::mul(*c, symbol(data, m, w, sym)));
                }
                put_symbol(parity, p, w, sym, acc);
            }
        }
        Ok(())
    }

    /// Rebuilds the `k` data chunks from any `k` received chunks.
    /// `positions[i]` is the codeword position of `received` chunk `i`, in
    /// `0..n`; `out` receives `k` chunks of `w` bytes in order.
    pub fn decode(
        self,
        w: usize,
        positions: &[usize],
        received: &[u8],
        out: &mut [u8],
    ) -> Result<(), Error> {
        if !w.is_multiple_of(2)
            || positions.len() != self.k
            || received.len() != self.k * w
            || out.len() != self.k * w
        {
            return Err(Error::Length);
        }

        for (i, &p) in positions.iter().enumerate() {
            if p >= self.n() || positions.iter().skip(i + 1).any(|&q| q == p) {
                return Err(Error::Length);
            }
        }

        // The rows of G at the received positions, then their inverse.
        let inv_top = self.vandermonde_top().inverse()?;
        let mut sub = Matrix::zero(self.k);
        let mut row = [0u16; MAX_K];
        for (i, &p) in positions.iter().enumerate() {
            self.row(&inv_top, p, &mut row);
            for (c, &v) in row.iter().enumerate().take(self.k) {
                sub.set(i, c, v);
            }
        }

        let inv = sub.inverse()?;

        for sym in 0..w / 2 {
            for m in 0..self.k {
                let mut acc = 0u16;
                for i in 0..self.k {
                    acc = gf16::add(acc, gf16::mul(inv.at(m, i), symbol(received, i, w, sym)));
                }
                put_symbol(out, m, w, sym, acc);
            }
        }
        Ok(())
    }
}

fn symbol(chunks: &[u8], chunk: usize, w: usize, sym: usize) -> u16 {
    let at = chunk * w + 2 * sym;
    match (chunks.get(at), chunks.get(at + 1)) {
        (Some(&hi), Some(&lo)) => u16::from_be_bytes([hi, lo]),
        _ => 0,
    }
}

fn put_symbol(chunks: &mut [u8], chunk: usize, w: usize, sym: usize, v: u16) {
    let at = chunk * w + 2 * sym;
    if let Some(cell) = chunks.get_mut(at..at + 2) {
        cell.copy_from_slice(&v.to_be_bytes());
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

    #[test]
    fn any_k_of_n_rebuild_the_data() {
        for (k, r, w) in [(4usize, 2usize, 4usize), (18, 3, 8), (36, 5, 6), (72, 9, 4)] {
            let code = Code { k, r };
            let data: alloc_free::Vec = (0..k * w).map(|i| (i * 7 + 3) as u8).collect();
            let mut parity = alloc_free::zeros(r * w);
            code.encode(w, &data, &mut parity).unwrap();

            // Drop the first r data chunks, and take every parity chunk.
            let mut positions = alloc_free::Positions::new();
            let mut received = alloc_free::zeros(k * w);
            let mut at = 0;
            for p in r..k {
                positions.push(p);
                received[at..at + w].copy_from_slice(&data[p * w..(p + 1) * w]);
                at += w;
            }
            for p in 0..r {
                positions.push(k + p);
                received[at..at + w].copy_from_slice(&parity[p * w..(p + 1) * w]);
                at += w;
            }

            let mut out = alloc_free::zeros(k * w);
            code.decode(w, positions.as_slice(), &received, &mut out)
                .unwrap();
            assert_eq!(out.as_slice(), data.as_slice(), "k={k} r={r} w={w}");
        }
    }

    #[test]
    fn a_repeated_position_is_rejected() {
        let code = Code { k: 2, r: 1 };
        let mut out = [0u8; 4];
        assert_eq!(
            code.decode(2, &[0, 0], &[0u8; 4], &mut out),
            Err(Error::Length)
        );
        assert_eq!(
            code.decode(2, &[0, 3], &[0u8; 4], &mut out),
            Err(Error::Length)
        );
    }

    /// Fixed-capacity helpers that need no heap.
    mod alloc_free {
        pub struct Vec {
            buf: [u8; 512],
            len: usize,
        }

        impl core::iter::FromIterator<u8> for Vec {
            fn from_iter<I: IntoIterator<Item = u8>>(it: I) -> Self {
                let mut v = Self {
                    buf: [0; 512],
                    len: 0,
                };
                for b in it {
                    v.buf[v.len] = b;
                    v.len += 1;
                }
                v
            }
        }

        impl core::ops::Deref for Vec {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                &self.buf[..self.len]
            }
        }

        impl core::ops::DerefMut for Vec {
            fn deref_mut(&mut self) -> &mut [u8] {
                &mut self.buf[..self.len]
            }
        }

        impl Vec {
            pub fn as_slice(&self) -> &[u8] {
                self
            }
        }

        pub fn zeros(n: usize) -> Vec {
            core::iter::repeat_n(0u8, n).collect()
        }

        pub struct Positions {
            buf: [usize; 96],
            len: usize,
        }

        impl Positions {
            pub fn new() -> Self {
                Self {
                    buf: [0; 96],
                    len: 0,
                }
            }

            pub fn push(&mut self, p: usize) {
                self.buf[self.len] = p;
                self.len += 1;
            }

            pub fn as_slice(&self) -> &[usize] {
                &self.buf[..self.len]
            }
        }
    }
}
