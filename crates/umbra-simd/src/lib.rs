//! The one crate of the UMBRA workspace that permits `unsafe` code (Part 14
//! §14.3).
//!
//! It holds no SIMD path yet. It holds [`WipingAlloc`], the global
//! allocator of the Android library (Part 14 `IMP-200`). UniFFI frees each
//! buffer that it lowers a value through with no overwrite, and it gives the
//! core no hook (`IMP-124`). Thus the allocator overwrites each block with
//! zero bytes before it frees it.
#![deny(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{compiler_fence, Ordering};
use std::alloc::System;

/// An allocator that overwrites each block with zero bytes before it frees
/// it. It runs over [`System`] by default.
///
/// `realloc` is the default of [`GlobalAlloc`]: an allocation, a copy, and
/// a free of the old block through `dealloc`. Thus the old block gets the
/// wipe too. The `realloc` of `System` can move a block or shrink it in
/// place, and then free the old block or the tail with no wipe.
#[derive(Debug, Clone, Copy, Default)]
pub struct WipingAlloc<A = System>(A);

impl WipingAlloc {
    /// The allocator over [`System`], for a `#[global_allocator]` static.
    pub const fn new() -> Self {
        Self(System)
    }
}

#[allow(unsafe_code)]
// SAFETY: each method forwards to the inner allocator, which keeps the
// contract of `GlobalAlloc`. `dealloc` writes only inside the block that it
// frees, and only before the free.
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipingAlloc<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller keeps the contract of `alloc`.
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller keeps the contract of `alloc_zeroed`.
        unsafe { self.0.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller gives a live block of this allocator under
        // `layout`, thus the block is valid for writes of its size.
        unsafe { wipe_raw(ptr, layout.size()) };

        // SAFETY: the inner allocator gave the block under `layout`.
        unsafe { self.0.dealloc(ptr, layout) }
    }
}

/// Overwrites each byte of `bytes` with zero, by writes that the compiler
/// keeps.
#[allow(unsafe_code)]
pub fn wipe(bytes: &mut [u8]) {
    // SAFETY: the slice is valid for writes of its length.
    unsafe { wipe_raw(bytes.as_mut_ptr(), bytes.len()) }
}

/// Overwrites `len` bytes from `start` with zero.
///
/// A plain fill before a free is a dead store, and the compiler can remove
/// it. A volatile write stays. The fence keeps each later access, such as
/// the free, after the writes.
///
/// # Safety
///
/// `start` must be valid for writes of `len` bytes.
#[allow(unsafe_code)]
unsafe fn wipe_raw(start: *mut u8, len: usize) {
    let word_size = core::mem::size_of::<usize>();
    let head = start.align_offset(core::mem::align_of::<usize>()).min(len);
    let word_count = (len - head) / word_size;
    let tail = head + word_count * word_size;

    // SAFETY: each write is inside the `len` bytes from `start`. The words
    // start at an aligned address, and they end at `tail`, which is at most
    // `len`.
    unsafe {
        for offset in 0..head {
            start.add(offset).write_volatile(0);
        }
        let words = start.add(head).cast::<usize>();
        for index in 0..word_count {
            words.add(index).write_volatile(0);
        }
        for offset in tail..len {
            start.add(offset).write_volatile(0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
#[allow(unsafe_code, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use core::sync::atomic::AtomicUsize;

    use super::*;

    // Each test of this binary, and the harness, runs on the allocator.
    #[global_allocator]
    static GLOBAL: WipingAlloc = WipingAlloc::new();

    /// An inner allocator that reads each block at its free. The block is
    /// still live then, thus the read is a reliable check of the wipe.
    struct Probe {
        freed: AtomicUsize,
        dirty: AtomicUsize,
    }

    impl Probe {
        const fn new() -> Self {
            Self {
                freed: AtomicUsize::new(0),
                dirty: AtomicUsize::new(0),
            }
        }
    }

    // SAFETY: each method forwards to `System`. `dealloc` reads the block
    // only before the free.
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller keeps the contract of `alloc`.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the block is live, and each test writes each byte of
            // it before the free.
            let block = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            if block.iter().any(|&byte| byte != 0) {
                self.dirty.fetch_add(1, Ordering::Relaxed);
            }
            self.freed.fetch_add(1, Ordering::Relaxed);

            // SAFETY: `System` gave the block under `layout`.
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    fn pattern(index: usize) -> u8 {
        u8::try_from(index % 251 + 1).unwrap()
    }

    #[test]
    fn a_wipe_clears_each_byte_of_its_range_and_no_other() {
        let mut buffer = [0xA5_u8; 96];

        // Each start takes another alignment, thus each length runs a head,
        // the words, and a tail in each mix.
        for start in 0..16 {
            for len in 0..=64 {
                buffer.fill(0xA5);
                wipe(&mut buffer[start..start + len]);

                assert!(buffer[..start].iter().all(|&byte| byte == 0xA5));
                assert!(buffer[start..start + len].iter().all(|&byte| byte == 0));
                assert!(buffer[start + len..].iter().all(|&byte| byte == 0xA5));
            }
        }
    }

    #[test]
    fn a_freed_block_is_zero_bytes_before_its_free() {
        let alloc = WipingAlloc(Probe::new());
        let layout = Layout::from_size_align(1_000, 16).unwrap();

        // SAFETY: the layout has a size, and the block is freed once under it.
        unsafe {
            let block = alloc.alloc(layout);
            assert!(!block.is_null());
            block.write_bytes(0xA5, layout.size());
            alloc.dealloc(block, layout);
        }

        assert_eq!(alloc.0.freed.load(Ordering::Relaxed), 1);
        assert_eq!(alloc.0.dirty.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_reallocation_keeps_the_contents_and_wipes_the_block_that_it_leaves() {
        let alloc = WipingAlloc(Probe::new());
        let small = Layout::from_size_align(64, 8).unwrap();
        let large = Layout::from_size_align(4_096, 8).unwrap();
        let shrunk = Layout::from_size_align(16, 8).unwrap();

        // SAFETY: each pointer is the live block of its layout when it is
        // used, and each block is freed once.
        unsafe {
            let block = alloc.alloc(small);
            assert!(!block.is_null());
            for index in 0..small.size() {
                block.add(index).write(pattern(index));
            }

            let grown = alloc.realloc(block, small, large.size());
            assert!(!grown.is_null());
            for index in 0..small.size() {
                assert_eq!(grown.add(index).read(), pattern(index));
            }
            for index in small.size()..large.size() {
                grown.add(index).write(pattern(index));
            }

            let kept = alloc.realloc(grown, large, shrunk.size());
            assert!(!kept.is_null());
            for index in 0..shrunk.size() {
                assert_eq!(kept.add(index).read(), pattern(index));
            }
            alloc.dealloc(kept, shrunk);
        }

        assert_eq!(alloc.0.freed.load(Ordering::Relaxed), 3);
        assert_eq!(alloc.0.dirty.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_vector_and_a_box_keep_their_contents_on_the_global_allocator() {
        let mut bytes = Vec::with_capacity(4);
        for index in 0..10_000 {
            bytes.push(pattern(index));
        }
        bytes.truncate(100);
        bytes.shrink_to_fit();
        assert!(bytes
            .iter()
            .enumerate()
            .all(|(index, &byte)| byte == pattern(index)));

        let zeroed = vec![0_u64; 1_000];
        assert!(zeroed.iter().all(|&word| word == 0));

        #[repr(align(64))]
        struct Aligned([u8; 64]);
        let boxed = Box::new(Aligned([7; 64]));
        assert_eq!(core::ptr::from_ref(&*boxed).addr() % 64, 0);
        assert!(boxed.0.iter().all(|&byte| byte == 7));
    }
}
