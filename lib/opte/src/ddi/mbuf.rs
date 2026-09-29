// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Edgecast Cloud LLC.

//! FreeBSD `mbuf` backing for [`MsgBlk`].
//!
//! This module mirrors the API of the illumos `mblk_t` backend so the
//! engine is unchanged: `m_next` plays the role of `b_cont`, and
//! `m_nextpkt` the role of `b_next`.
//!
//! OPTE's offload state (the value illumos keeps in `db_struioun`) lives
//! in `m_pkthdr.PH_loc` of the head mbuf while OPTE owns the packet.
//! Network drivers never read it. [`MsgBlk::import_rx_offload`] seeds it
//! from `csum_flags` when a packet arrives from the stack; turning it
//! back into `csum_flags` for transmit is the caller's job, since that
//! needs the parse info. `m_pkthdr.len` is only brought up to date by
//! [`MsgBlk::unwrap_mblk`].

use crate::engine::packet::BufferState;
use crate::engine::packet::Pullup;
use crate::engine::packet::SegAdjustError;
use crate::engine::packet::WrapError;
use crate::engine::packet::WriteError;
use alloc::vec::Vec;
use core::cmp::Ordering;
#[cfg(all(not(feature = "std"), not(test)))]
use core::ffi::c_int;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::num::NonZeroUsize;
use core::ops::Deref;
use core::ops::DerefMut;
use core::ptr;
use core::ptr::NonNull;
use core::slice;
use freebsd_sys_hdrs as sys;
pub use freebsd_sys_hdrs::mbuf;
use illumos_sys_hdrs::mac::MblkOffloadFlags;
use illumos_sys_hdrs::mac::mac_ether_offload_info_t;
use illumos_sys_hdrs::uintptr_t;
use ingot::types::Emit;
use ingot::types::EmitDoesNotRelyOnBufContents;
use ingot::types::ParseError as IngotParseErr;
use ingot::types::Read;

/// The raw OS packet type behind a [`MsgBlk`].
pub type RawBuf = mbuf;

pub static MBLK_MAX_SIZE: usize = u16::MAX as usize;

/// Buffers above the largest mbuf cluster we ask for are allocated here
/// and attached with `m_extadd`.
const LARGE_BUF_ALIGN: usize = 64;

/// Large buffers whose free routine lives in this module and has not run
/// yet. The module must not unload while this is nonzero.
#[cfg(all(not(feature = "std"), not(test)))]
static LARGE_BUFS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// The number of mbufs in the system that still point at this module's
/// free routine.
#[cfg(all(not(feature = "std"), not(test)))]
pub fn large_bufs_outstanding() -> usize {
    LARGE_BUFS.load(core::sync::atomic::Ordering::Acquire)
}

/// Abstractions over an `mbuf` which can be returned to their raw
/// pointer representation.
pub trait AsMblk {
    /// Consume `self`, returning the underlying `mbuf`. The caller of
    /// this function now owns the underlying segment chain.
    fn unwrap_mblk(self) -> Option<NonNull<mbuf>>;

    /// Consume `self`, returning the head and tail packets. If the chain
    /// contains a single packet, then the tail will be equal to the head.
    fn unwrap_head_and_tail(self) -> Option<(NonNull<mbuf>, NonNull<mbuf>)>
    where
        Self: Sized,
    {
        // SAFETY: `v`, if present, is a valid mbuf.
        self.unwrap_mblk().map(|v| unsafe { (v, find_pkt_tail(v)) })
    }
}

/// Find the last packet in an `m_nextpkt` list.
///
/// # Safety
/// `head` must point to a valid mbuf whose `m_nextpkt` list has no loops.
unsafe fn find_pkt_tail(head: NonNull<mbuf>) -> NonNull<mbuf> {
    let mut tail = head;
    unsafe {
        while let Some(next) = NonNull::new((*tail.as_ptr()).m_nextpkt) {
            tail = next;
        }
    }
    tail
}

struct MsgBlkChainInner {
    head: NonNull<mbuf>,
    tail: NonNull<mbuf>,
}

/// A list of packets linked through `m_nextpkt`.
pub struct MsgBlkChain(Option<MsgBlkChainInner>);

// SAFETY: chain-modifying operations require `&mut`, and mbufs carry no
// thread-local state.
unsafe impl Send for MsgBlkChain {}
unsafe impl Sync for MsgBlkChain {}

impl Default for MsgBlkChain {
    fn default() -> Self {
        Self::empty()
    }
}

impl MsgBlkChain {
    pub const fn empty() -> Self {
        Self(None)
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// Convert an `m_nextpkt` list into a safe source of `MsgBlk`s.
    ///
    /// # Safety
    /// `mp` must be an mbuf packet list owned by the caller, with no
    /// loops. The original pointer must not be used again.
    pub unsafe fn new(mp: *mut mbuf) -> Result<Self, WrapError> {
        let head = NonNull::new(mp).ok_or(WrapError::NullPtr)?;
        let tail = unsafe { find_pkt_tail(head) };
        Ok(Self(Some(MsgBlkChainInner { head, tail })))
    }

    /// Removes the next packet from the front of the list, taking
    /// ownership of it.
    pub fn pop_front(&mut self) -> Option<MsgBlk> {
        let list = self.0.as_mut()?;
        unsafe {
            let curr = list.head.as_ptr();
            let next = NonNull::new((*curr).m_nextpkt);
            (*curr).m_nextpkt = ptr::null_mut();

            match next {
                Some(next) => list.head = next,
                None => self.0 = None,
            }

            Some(MsgBlk(NonNull::new_unchecked(curr)))
        }
    }

    /// Adds an owned `MsgBlk` to the end of this list.
    pub fn append(&mut self, packet: MsgBlk) {
        let pkt = packet.unwrap_mblk();

        unsafe {
            assert!((*pkt.as_ptr()).m_nextpkt.is_null());
        }

        match &mut self.0 {
            Some(list) => {
                unsafe { (*list.tail.as_ptr()).m_nextpkt = pkt.as_ptr() };
                list.tail = pkt;
            }
            None => {
                self.0 = Some(MsgBlkChainInner { head: pkt, tail: pkt });
            }
        }
    }
}

impl AsMblk for MsgBlkChain {
    fn unwrap_mblk(mut self) -> Option<NonNull<mbuf>> {
        self.0.take().map(|v| v.head)
    }

    fn unwrap_head_and_tail(
        mut self,
    ) -> Option<(NonNull<mbuf>, NonNull<mbuf>)> {
        self.0.take().map(|v| (v.head, v.tail))
    }
}

impl Drop for MsgBlkChain {
    fn drop(&mut self) {
        while let Some(pkt) = self.pop_front() {
            drop(pkt);
        }
    }
}

/// A single packet: an mbuf chain linked through `m_next`.
///
/// Every `MsgBlk` created here has `M_PKTHDR` on its head mbuf.
#[derive(Debug)]
pub struct MsgBlk(NonNull<mbuf>);

impl Deref for MsgBlk {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { seg_slice(self.0.as_ptr()) }
    }
}

impl DerefMut for MsgBlk {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { seg_slice_mut(self.0.as_ptr()) }
    }
}

unsafe fn seg_len(m: *const mbuf) -> usize {
    unsafe { (*m).m_len.max(0) as usize }
}

unsafe fn seg_slice<'a>(m: *const mbuf) -> &'a [u8] {
    unsafe {
        let len = seg_len(m);
        if len == 0 {
            return &[];
        }
        slice::from_raw_parts((*m).m_data as *const u8, len)
    }
}

unsafe fn seg_slice_mut<'a>(m: *mut mbuf) -> &'a mut [u8] {
    unsafe {
        let len = seg_len(m);
        if len == 0 {
            return &mut [];
        }
        slice::from_raw_parts_mut((*m).m_data as *mut u8, len)
    }
}

impl MsgBlk {
    /// Allocate a new [`MsgBlk`] containing a single, unshared data
    /// buffer of at least `len` bytes.
    pub fn new(len: usize) -> Self {
        Self::try_new(len).expect("somehow failed to get an mbuf...")
    }

    fn try_new(len: usize) -> Option<Self> {
        NonNull::new(allocb(len)).map(Self)
    }

    /// Allocates a new [`MsgBlk`] of size `buf.len()`, copying its
    /// contents.
    pub fn copy(buf: impl AsRef<[u8]>) -> Self {
        let mut out = Self::new(buf.as_ref().len());
        // Unwrap safety -- just allocated length of input buffer.
        out.write_bytes_back(buf).unwrap();
        out
    }

    /// Copy the first `n` bytes of this packet into a new head buffer.
    /// The remaining bytes follow in segments that share storage with
    /// this packet where the kernel allows it.
    pub fn pullup(
        &self,
        n: Option<NonZeroUsize>,
    ) -> Result<Self, PktPullupError> {
        let totlen = self.byte_len();

        if let Some(n) = n
            && n.get() > totlen
        {
            return Err(PktPullupError::TooLong);
        }

        let head_len = n.map(|v| v.get()).unwrap_or(totlen);
        let mut top =
            Self::try_new(head_len).ok_or(PktPullupError::AllocFailed)?;

        let mut still_to_write = head_len;
        for chunk in self.iter() {
            if still_to_write == 0 {
                break;
            }
            let to_take = chunk.len().min(still_to_write);
            top.write_bytes_back(&chunk[..to_take])
                .expect("to_take should be <= remaining capacity");
            still_to_write -= to_take;
        }

        if head_len < totlen {
            let rest =
                copy_tail(self, head_len).ok_or(PktPullupError::AllocFailed)?;
            unsafe { (*top.0.as_ptr()).m_next = rest.as_ptr() };
        }

        self.copy_offload_info_to(&mut top);

        Ok(top)
    }

    /// Creates a new [`MsgBlk`] using a given set of packet headers.
    pub fn new_pkt(emit: impl Emit + EmitDoesNotRelyOnBufContents) -> Self {
        let mut pkt = Self::new(emit.packet_length());
        pkt.emit_back(emit).unwrap();
        pkt
    }

    /// Returns the number of bytes available for writing ahead of the
    /// data in the head buffer. This is zero if the buffer is shared or
    /// read-only.
    pub fn head_capacity(&self) -> usize {
        unsafe { sys::m_leadingspace(self.0.as_ptr()) }
    }

    /// Returns the number of bytes available for writing after the
    /// data in the head buffer. This is zero if the buffer is shared or
    /// read-only.
    pub fn tail_capacity(&self) -> usize {
        unsafe { sys::m_trailingspace(self.0.as_ptr()) }
    }

    /// Returns the number of bytes allocated in all buffers in this
    /// packet.
    pub fn all_segs_capacity(&self) -> usize {
        self.iter().map(|v| unsafe { sys::m_size(&v.0) }).sum()
    }

    /// Creates a new [`MsgBlk`] containing a data buffer of `len`
    /// bytes with 2B of headroom/alignment.
    pub fn new_ethernet(len: usize) -> Self {
        Self::new_with_headroom(2, len)
    }

    /// Creates a new [`MsgBlk`] using a given set of packet headers
    /// with 2B of headroom/alignment.
    pub fn new_ethernet_pkt(
        emit: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Self {
        let mut pkt = Self::new_ethernet(emit.packet_length());
        pkt.emit_back(emit).unwrap();
        pkt
    }

    /// Return the number of bytes in all segments.
    pub fn byte_len(&self) -> usize {
        unsafe { count_chain_bytes(Some(self.0)) }
    }

    /// Return the number of segments.
    pub fn seg_len(&self) -> usize {
        self.iter().len()
    }

    /// Truncates the segment chain so it holds at most `len` bytes.
    pub fn truncate_chain(&mut self, len: usize) {
        let mut seen = 0;
        let mut curr = Some(self.0);
        let mut old_tail = ptr::null_mut();

        while let Some(valid_curr) = curr.take() {
            let valid_curr = valid_curr.as_ptr();
            let seg = unsafe { seg_len(valid_curr) };
            let seen_til_now = seen;
            seen += seg;

            if seen >= len {
                let to_keep = len.saturating_sub(seen_til_now);
                unsafe {
                    (*valid_curr).m_len = to_keep as i32;
                    core::ptr::swap(
                        &raw mut (*valid_curr).m_next,
                        &raw mut old_tail,
                    );
                }
            } else {
                curr = NonNull::new(unsafe { (*valid_curr).m_next });
            }
        }

        free_chain(old_tail);
    }

    /// Allocate a new [`MsgBlk`] with `head_len` bytes of headroom and
    /// `body_len` bytes of capacity at the back.
    pub fn new_with_headroom(head_len: usize, body_len: usize) -> Self {
        let out = Self::new(head_len + body_len);
        unsafe {
            let m = out.0.as_ptr();
            (*m).m_data = (*m).m_data.add(head_len);
            (*m).m_len = 0;
        }
        out
    }

    /// Provides a slice of length `n_bytes` after the data in the head
    /// buffer to be initialised, before increasing its length by
    /// `n_bytes`.
    ///
    /// # Safety
    /// Users must write a value to every element of the `MaybeUninit`
    /// buffer at least once in the `MsgBlk` lifecycle -- all `n_bytes`
    /// are assumed to be initialised.
    pub unsafe fn write_back(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) -> Result<(), WriteError> {
        let available = self.tail_capacity();
        if available < n_bytes {
            return Err(WriteError::NotEnoughBytes {
                available,
                needed: n_bytes,
            });
        }

        let m = self.0.as_ptr();
        unsafe {
            let tail = (*m).m_data.add(seg_len(m)) as *mut MaybeUninit<u8>;
            f(slice::from_raw_parts_mut(tail, n_bytes));
            (*m).m_len += n_bytes as i32;
        }

        Ok(())
    }

    /// Provides a slice of length `n_bytes` ahead of the data in the head
    /// buffer to be initialised, before increasing its length by
    /// `n_bytes`.
    ///
    /// # Safety
    /// Users must write a value to every element of the `MaybeUninit`
    /// buffer at least once in the `MsgBlk` lifecycle -- all `n_bytes`
    /// are assumed to be initialised.
    pub unsafe fn write_front(
        &mut self,
        n_bytes: usize,
        f: impl FnOnce(&mut [MaybeUninit<u8>]),
    ) -> Result<(), WriteError> {
        let available = self.head_capacity();
        if available < n_bytes {
            return Err(WriteError::NotEnoughBytes {
                available,
                needed: n_bytes,
            });
        }

        let m = self.0.as_ptr();
        unsafe {
            let new_head = (*m).m_data.sub(n_bytes);
            f(slice::from_raw_parts_mut(
                new_head as *mut MaybeUninit<u8>,
                n_bytes,
            ));
            (*m).m_data = new_head;
            (*m).m_len += n_bytes as i32;
        }

        Ok(())
    }

    /// Sets the length of the head buffer, initialising any extra bytes
    /// to 0.
    pub fn resize(&mut self, new_len: usize) -> Result<(), WriteError> {
        let len = self.len();
        match new_len.cmp(&len) {
            Ordering::Less => {
                unsafe { (*self.0.as_ptr()).m_len = new_len as i32 };
                Ok(())
            }
            Ordering::Greater => unsafe {
                self.write_back(new_len - len, |v| {
                    let n = v.len();
                    v.as_mut_ptr().write_bytes(0, n);
                })
            },
            Ordering::Equal => Ok(()),
        }
    }

    /// Grows the head buffer at the front by `n` zeroed bytes.
    pub fn expand_front(&mut self, n: usize) -> Result<(), SegAdjustError> {
        unsafe {
            self.write_front(n, |v| {
                let n = v.len();
                v.as_mut_ptr().write_bytes(0, n);
            })
            .map_err(|_| SegAdjustError::StartBeforeBase)
        }
    }

    /// Removes `n` bytes from the start of the head buffer.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartPastEnd`: the head buffer holds fewer than
    /// `n` bytes.
    pub fn drop_front_bytes(&mut self, n: usize) -> Result<(), SegAdjustError> {
        let node = self
            .iter_mut()
            .next()
            .expect("There will always be a front element by definition");

        node.drop_front_bytes(n)
    }

    /// Emits an `ingot` packet after any bytes present in the head buffer.
    pub fn emit_back(
        &mut self,
        pkt: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Result<(), WriteError> {
        unsafe {
            self.write_back(pkt.packet_length(), |v| {
                pkt.emit_uninit(v).unwrap();
            })
        }
    }

    /// Emits an `ingot` packet before any bytes present in the head
    /// buffer.
    pub fn emit_front(
        &mut self,
        pkt: impl Emit + EmitDoesNotRelyOnBufContents,
    ) -> Result<(), WriteError> {
        unsafe {
            self.write_front(pkt.packet_length(), |v| {
                pkt.emit_uninit(v).unwrap();
            })
        }
    }

    /// Copies a byte slice in after any bytes present in the head buffer.
    pub fn write_bytes_back(
        &mut self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), WriteError> {
        let bytes = bytes.as_ref();
        unsafe {
            self.write_back(bytes.len(), |v| {
                let uninit_src: &[MaybeUninit<u8>] =
                    core::mem::transmute(bytes);
                v.copy_from_slice(uninit_src);
            })
        }
    }

    /// Copies a byte slice in before any bytes present in the head
    /// buffer.
    pub fn write_bytes_front(
        &mut self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), WriteError> {
        let bytes = bytes.as_ref();
        unsafe {
            self.write_front(bytes.len(), |v| {
                let uninit_src: &[MaybeUninit<u8>] =
                    core::mem::transmute(bytes);
                v.copy_from_slice(uninit_src);
            })
        }
    }

    /// Places another `MsgBlk` at the end of this packet's segment chain.
    ///
    /// When this packet's head was freshly allocated and `other` came
    /// from the stack, `other`'s flow metadata moves to the head, as
    /// `M_PREPEND` would do. Offload state is not moved; use
    /// [`Self::copy_offload_info_to`] for that.
    pub fn append(&mut self, other: Self) {
        let other = other.unwrap_mblk().as_ptr();
        let mut curr = self.0.as_ptr();
        unsafe {
            if (*other).has_flags(sys::M_PKTHDR) {
                if !has_flow_metadata(curr) {
                    move_flow_metadata(curr, other);
                }
                demote_pkthdr(other);
            }
            while !(*curr).m_next.is_null() {
                curr = (*curr).m_next;
            }
            (*curr).m_next = other;
        }
    }

    /// Drop all bytes and move the data pointer to the very back of the
    /// head buffer.
    pub fn pop_all(&mut self) {
        let m = self.0.as_ptr();
        unsafe {
            (*m).m_data = sys::m_start(m).add(sys::m_size(m));
            (*m).m_len = 0;
        }
    }

    /// Returns a shared cursor over all segments.
    pub fn iter(&self) -> MsgBlkIter<'_> {
        MsgBlkIter { curr: Some(self.0), marker: PhantomData }
    }

    /// Returns a mutable cursor over all segments.
    pub fn iter_mut(&mut self) -> MsgBlkIterMut<'_> {
        MsgBlkIterMut { curr: Some(self.0), marker: PhantomData }
    }

    /// Return the address of the head mbuf, for probe context.
    pub fn mblk_addr(&self) -> uintptr_t {
        self.0.as_ptr() as uintptr_t
    }

    /// Return the head of the mbuf chain and consume `self`, with
    /// `m_pkthdr.len` set to the chain's length. The caller now owns the
    /// chain.
    pub fn unwrap_mblk(self) -> NonNull<mbuf> {
        AsMblk::unwrap_mblk(self)
            .expect("unwrapping a single mbuf is always infallible")
    }

    /// Wrap an mbuf packet in a [`MsgBlk`], taking ownership of it. The
    /// chain is freed when the `MsgBlk` is dropped.
    ///
    /// A packet taken from the network stack must be followed by
    /// [`Self::import_rx_offload`], since `PH_loc` may hold another
    /// layer's scratch data.
    ///
    /// # Safety
    ///
    /// `ptr` must be an mbuf chain owned by the caller. Any segment the
    /// engine reads or writes through a slice must not be modified
    /// concurrently by anyone else; storage shared with a guest must be
    /// copied into a private buffer first.
    ///
    /// # Errors
    ///
    /// * [`WrapError::NullPtr`] if `ptr` is null.
    /// * [`WrapError::Chain`] if `ptr->m_nextpkt` is set.
    pub unsafe fn wrap_mblk(ptr: *mut mbuf) -> Result<Self, WrapError> {
        let inner = NonNull::new(ptr).ok_or(WrapError::NullPtr)?;
        unsafe {
            if (*inner.as_ptr()).m_nextpkt.is_null() {
                Ok(Self(inner))
            } else {
                Err(WrapError::Chain)
            }
        }
    }

    /// Copy out all bytes of this packet into a single contiguous buffer.
    pub fn copy_all(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        for node in self.iter() {
            out.extend_from_slice(node)
        }
        out
    }

    /// Drops all empty segments from the start of the chain where
    /// another segment follows.
    ///
    /// The new head keeps the old head's packet header, so it may be
    /// replaced by a copy when its storage overlaps where a header goes.
    pub fn drop_empty_segments(&mut self) {
        let old_head = self.0.as_ptr();
        let mut head = old_head;
        let mut prev = ptr::null_mut();

        unsafe {
            while !(*head).m_next.is_null() && (*head).m_len == 0 {
                prev = head;
                head = (*head).m_next;
            }

            if head == old_head {
                return;
            }

            let Some(new_head) = promote_to_head(head, old_head) else {
                // Empty segments are harmless to busdma; keep them rather
                // than fail.
                return;
            };

            // If `head` was replaced by a copy, the prefix still links to
            // it and frees it.
            if new_head == head {
                (*prev).m_next = ptr::null_mut();
            }
            free_chain(old_head);
            self.0 = NonNull::new_unchecked(new_head);
        }
    }

    /// Copies the offload information from this packet to another,
    /// including checksum/LSO flags and TCP MSS (if set).
    pub fn copy_offload_info_to(&self, other: &mut Self) {
        unsafe {
            let info = offload_info(self.0);
            set_offload_info(other.0, info);
        }
    }

    /// Return the number of references to the head buffer's storage. A
    /// read-only buffer counts as shared.
    pub fn ref_count(&self) -> usize {
        unsafe {
            let m = self.0.as_ptr();
            let flags = (*m).m_flags();
            let count = if flags & sys::M_EXT != 0 {
                sys::m_extrefcnt(m) as usize
            } else {
                1
            };
            if flags & sys::M_RDONLY != 0 { count.max(2) } else { count }
        }
    }

    /// Sets a packet's offload flags, and sets MSS if `HW_LSO` is enabled.
    pub fn request_offload(&mut self, flags: MblkOffloadFlags, mss: u32) {
        unsafe { request_mblk_offload(self.0, flags, mss) }
    }

    /// Record header lengths for tunnel-aware offloads in `m_pkthdr`.
    /// The encapsulation type flag is left to the caller: FreeBSD 15 has
    /// no `CSUM_ENCAP_GENEVE`, and its bit is reserved there.
    pub fn fill_parse_info(
        &mut self,
        outer_meoi: &mac_ether_offload_info_t,
        inner_meoi: Option<&mac_ether_offload_info_t>,
    ) -> Result<(), PktInfoError> {
        if self.ref_count() > 1 {
            return Err(PktInfoError::PacketShared);
        }

        let m = self.0.as_ptr();
        unsafe {
            if !(*m).has_flags(sys::M_PKTHDR) {
                return Ok(());
            }

            let mut lens = sys::pkthdr_hdrlens {
                l2hlen: outer_meoi.meoi_l2hlen,
                l3hlen: hdrlen_u8(outer_meoi.meoi_l3hlen),
                l4hlen: outer_meoi.meoi_l4hlen,
                l5hlen: hdrlen_u8(outer_meoi.meoi_tunhlen),
                ..Default::default()
            };
            if let Some(inner) = inner_meoi {
                lens.inner_l2hlen = inner.meoi_l2hlen;
                lens.inner_l3hlen = hdrlen_u8(inner.meoi_l3hlen);
                lens.inner_l4hlen = inner.meoi_l4hlen;
            }

            (*m).pkthdr_mut().set_hdrlens(lens);
        }

        Ok(())
    }

    /// Return the offloads currently requested by a packet.
    pub fn offload_flags(&self) -> MblkOffloadInfo {
        unsafe { typed_offload_info(self.0) }
    }

    /// Seed OPTE's offload state from the checksum results the stack or
    /// driver recorded in `csum_flags`.
    pub fn import_rx_offload(&mut self) {
        let m = self.0.as_ptr();
        unsafe {
            if !(*m).has_flags(sys::M_PKTHDR) {
                return;
            }
            let csum = (*m).pkthdr().csum_flags;
            let both = |bits: u32| csum & bits == bits;

            let mut flags = MblkOffloadFlags::empty();
            if both(sys::CSUM_L3_CALC | sys::CSUM_L3_VALID) {
                flags |= MblkOffloadFlags::HCK_IPV4_HDRCKSUM_OK;
            }
            if both(sys::CSUM_L4_CALC | sys::CSUM_L4_VALID) {
                flags |= MblkOffloadFlags::HCK_FULLCKSUM_OK;
            }
            if both(sys::CSUM_INNER_L3_CALC | sys::CSUM_INNER_L3_VALID) {
                flags |= MblkOffloadFlags::HCK_INNER_V4CKSUM_OK;
            }
            if both(sys::CSUM_INNER_L4_CALC | sys::CSUM_INNER_L4_VALID) {
                flags |= MblkOffloadFlags::HCK_INNER_FULL_OK;
            }

            let info =
                CksumInternal { cksum: 0, flags: flags.bits() as u16, mss: 0 };
            set_offload_info(self.0, zerocopy::transmute!(info));
        }
    }
}

/// `m_pkthdr` header lengths are one byte; longer headers are left for
/// the driver to find.
fn hdrlen_u8(len: u16) -> u8 {
    u8::try_from(len).unwrap_or(0)
}

/// Representation of OPTE's offload flags and MSS, as illumos lays out
/// `db_struioun`.
#[derive(zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::Immutable)]
#[repr(C)]
struct CksumInternal {
    cksum: u32,
    flags: u16,
    mss: u16,
}

pub(crate) unsafe fn request_mblk_offload(
    mp: NonNull<mbuf>,
    flags: MblkOffloadFlags,
    mss: u32,
) {
    let ckflags = flags & MblkOffloadFlags::HCK_FLAGS;
    let before = unsafe { offload_info(mp) };
    let mut info: CksumInternal = zerocopy::transmute!(before);
    info.flags = ckflags.bits() as u16;
    if flags.contains(MblkOffloadFlags::HW_LSO) {
        info.flags |= MblkOffloadFlags::HW_LSO.bits() as u16;
        info.mss = mss as u16;
    }
    unsafe { set_offload_info(mp, zerocopy::transmute!(info)) };
}

#[derive(Default)]
pub struct MblkOffloadInfo {
    pub flags: MblkOffloadFlags,
    pub mss: u32,
}

impl AsMblk for MsgBlk {
    fn unwrap_mblk(self) -> Option<NonNull<mbuf>> {
        let ptr_out = self.0;
        let len = self.byte_len();
        _ = ManuallyDrop::new(self);
        unsafe {
            let m = ptr_out.as_ptr();
            if (*m).has_flags(sys::M_PKTHDR) {
                (*m).pkthdr_mut().len = len as i32;
            }
        }
        Some(ptr_out)
    }

    fn unwrap_head_and_tail(self) -> Option<(NonNull<mbuf>, NonNull<mbuf>)> {
        let out = self.unwrap_mblk();
        Some((out, out))
    }
}

/// A segment of a [`MsgBlk`]'s chain, accessed via iterator.
#[repr(transparent)]
pub struct MsgBlkNode(mbuf);

impl core::fmt::Debug for MsgBlkNode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MsgBlkNode")
            .field("m_data", &self.0.m_data)
            .field("m_len", &self.0.m_len)
            .field("m_flags", &self.0.m_flags())
            .finish()
    }
}

impl Deref for MsgBlkNode {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { seg_slice(&self.0) }
    }
}

impl DerefMut for MsgBlkNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { seg_slice_mut(&mut self.0) }
    }
}

impl MsgBlkNode {
    /// Removes `n` bytes from the start of this segment.
    ///
    /// # Errors
    ///
    /// `SegAdjustError::StartPastEnd`: the segment holds fewer than `n`
    /// bytes.
    pub fn drop_front_bytes(&mut self, n: usize) -> Result<(), SegAdjustError> {
        if (self.0.m_len.max(0) as usize) < n {
            return Err(SegAdjustError::StartPastEnd);
        }
        unsafe { self.0.m_data = self.0.m_data.add(n) };
        self.0.m_len -= n as i32;
        Ok(())
    }
}

#[derive(Debug)]
pub struct MsgBlkIter<'a> {
    curr: Option<NonNull<mbuf>>,
    marker: PhantomData<&'a MsgBlk>,
}

#[derive(Debug)]
pub struct MsgBlkIterMut<'a> {
    curr: Option<NonNull<mbuf>>,
    marker: PhantomData<&'a mut MsgBlk>,
}

impl MsgBlkIterMut<'_> {
    pub fn next_iter(&self) -> MsgBlkIter<'_> {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { (*ptr.as_ptr()).m_next }));
        MsgBlkIter { curr, marker: PhantomData }
    }

    pub fn next_iter_mut(&mut self) -> MsgBlkIterMut<'_> {
        let curr = self
            .curr
            .and_then(|ptr| NonNull::new(unsafe { (*ptr.as_ptr()).m_next }));
        MsgBlkIterMut { curr, marker: PhantomData }
    }
}

impl Pullup for MsgBlkIterMut<'_> {
    fn pullup(&self, prepend: Option<&[u8]>) -> MsgBlk {
        let prepend = prepend.unwrap_or_default();
        let bytes_in_self = BufferState::len(self);
        let mut new_seg = MsgBlk::new(prepend.len() + bytes_in_self);

        new_seg
            .write_bytes_back(prepend)
            .expect("allocated enough bytes for prepend and self");

        let offload_info = self.curr.map(|v| unsafe { offload_info(v) });

        if bytes_in_self != 0 {
            // Copy with raw pointers: the storage may be shared, so
            // taking a slice of it is not sound.
            unsafe {
                new_seg
                    .write_back(bytes_in_self, |mut buf| {
                        let mut curr = self.curr;
                        while let Some(valid_curr) = curr {
                            let m = valid_curr.as_ptr();
                            let len = seg_len(m);
                            let dst = buf.as_mut_ptr() as *mut u8;
                            dst.copy_from_nonoverlapping(
                                (*m).m_data as *const u8,
                                len,
                            );
                            curr = NonNull::new((*m).m_next);
                            buf = buf.split_at_mut(len).1;
                        }
                    })
                    .expect("allocated enough bytes for prepend and self");
            }
        }

        if let Some(info) = offload_info {
            unsafe { set_offload_info(new_seg.0, info) };
        }

        new_seg
    }
}

/// Reasons a [`MsgBlk`] could not have its parse information set.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum PktInfoError {
    /// The head buffer is shared.
    PacketShared,
}

impl core::error::Error for PktInfoError {}

impl core::fmt::Display for PktInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PacketShared => "packet has a reference count > 1",
        })
    }
}

/// Reasons a [`MsgBlk`] could not be pulled up.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Hash)]
pub enum PktPullupError {
    /// Requested pullup was longer than the underlying packet.
    TooLong,
    /// The OS was unable to allocate a [`MsgBlk`].
    AllocFailed,
}

impl core::error::Error for PktPullupError {}

impl core::fmt::Display for PktPullupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "requested pullup is longer than packet",
            Self::AllocFailed => "failed to allocate an mbuf",
        })
    }
}

unsafe fn count_chain(mut head: Option<NonNull<mbuf>>) -> usize {
    let mut count = 0;
    while let Some(valid_head) = head {
        count += 1;
        head = NonNull::new(unsafe { (*valid_head.as_ptr()).m_next });
    }
    count
}

unsafe fn count_chain_bytes(mut head: Option<NonNull<mbuf>>) -> usize {
    let mut count = 0;
    while let Some(valid_head) = head {
        unsafe {
            count += seg_len(valid_head.as_ptr());
            head = NonNull::new((*valid_head.as_ptr()).m_next);
        }
    }
    count
}

/// OPTE's opaque offload state for the packet whose head is `head`, or
/// zero if `head` has no packet header.
unsafe fn offload_info(head: NonNull<mbuf>) -> u64 {
    unsafe {
        let m = head.as_ptr();
        if (*m).has_flags(sys::M_PKTHDR) {
            (*m).pkthdr().ph_loc.ph_loc.sixtyfour[0]
        } else {
            0
        }
    }
}

unsafe fn set_offload_info(head: NonNull<mbuf>, info: u64) {
    unsafe {
        let m = head.as_ptr();
        if (*m).has_flags(sys::M_PKTHDR) {
            (*m).pkthdr_mut().ph_loc.ph_loc.sixtyfour[0] = info;
        }
    }
}

unsafe fn typed_offload_info(head: NonNull<mbuf>) -> MblkOffloadInfo {
    let raw = unsafe { offload_info(head) };
    let data: CksumInternal = zerocopy::transmute!(raw);
    MblkOffloadInfo {
        flags: MblkOffloadFlags::from_bits_retain(u32::from(data.flags)),
        mss: u32::from(data.mss),
    }
}

/// Whether `m`'s packet header says anything about where the packet came
/// from, as opposed to one OPTE just allocated.
unsafe fn has_flow_metadata(m: *const mbuf) -> bool {
    unsafe {
        if !(*m).has_flags(sys::M_PKTHDR) {
            return false;
        }
        let ph = (*m).pkthdr();
        !ph.rcvif.is_null()
            || !ph.tags.is_null()
            || ph.flowid != 0
            || ph.rsstype != 0
            || ph.fibnum != 0
    }
}

/// Move the flow-identifying parts of `from`'s packet header to `to`,
/// leaving `to`'s length, checksum and offload state alone.
unsafe fn move_flow_metadata(to: *mut mbuf, from: *mut mbuf) {
    unsafe {
        if !(*to).has_flags(sys::M_PKTHDR) {
            return;
        }
        let src = (*from).pkthdr_mut();
        let dst = (*to).pkthdr_mut();

        dst.rcvif = src.rcvif;
        dst.leaf_rcvif = src.leaf_rcvif;
        dst.flowid = src.flowid;
        dst.rsstype = src.rsstype;
        dst.fibnum = src.fibnum;
        dst.numa_domain = src.numa_domain;
        dst.csum_flags |= src.csum_flags & sys::CSUM_SND_TAG;

        // The tag list may only have one owner.
        if dst.tags.is_null() {
            dst.tags = src.tags;
            src.tags = ptr::null_mut();
        }

        src.rcvif = ptr::null_mut();
        src.csum_flags &= !sys::CSUM_SND_TAG;
    }
}

/// Turn `m` into a plain segment.
unsafe fn demote_pkthdr(m: *mut mbuf) {
    #[cfg(all(not(feature = "std"), not(test)))]
    unsafe {
        sys::m_demote_pkthdr(m)
    }

    #[cfg(any(feature = "std", test))]
    unsafe {
        mock::demote_pkthdr(m)
    }
}

/// Make `seg`, a later segment of `old_head`'s chain, the head of a
/// packet carrying `old_head`'s packet header. Returns the new head, or
/// `None` if memory is short.
///
/// A plain mbuf with internal storage keeps its data where a packet
/// header would go, so its bytes move to a fresh mbuf, which replaces
/// `seg` in the chain.
unsafe fn promote_to_head(
    seg: *mut mbuf,
    old_head: *mut mbuf,
) -> Option<*mut mbuf> {
    unsafe {
        let new_head = if (*seg).has_flags(sys::M_PKTHDR) {
            seg
        } else if (*seg).has_flags(sys::M_EXT) {
            let flags = (*seg).m_flags();
            (*seg).set_m_flags(flags | sys::M_PKTHDR);
            ptr::write_bytes((*seg).pkthdr_mut(), 0, 1);
            seg
        } else {
            let mut copy = MsgBlk::try_new(seg_len(seg))?;
            copy.write_bytes_back(seg_slice(seg))
                .expect("allocated enough bytes for the segment");
            let copy = ManuallyDrop::new(copy).0.as_ptr();

            // Swap `copy` in for `seg`; the prefix still links to `seg`,
            // so it is freed along with the prefix.
            (*copy).m_next = (*seg).m_next;
            (*seg).m_next = ptr::null_mut();
            copy
        };

        if (*old_head).has_flags(sys::M_PKTHDR) {
            let src = *(*old_head).pkthdr();
            let dst = (*new_head).pkthdr_mut();
            dst.ph_loc = src.ph_loc;
            dst.hdr = src.hdr;
            dst.ph_per = src.ph_per;
            dst.csum_flags = src.csum_flags & !sys::CSUM_SND_TAG;
            move_flow_metadata(new_head, old_head);
        }

        Some(new_head)
    }
}

impl<'a> Iterator for MsgBlkIter<'a> {
    type Item = &'a MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = self.curr?;
        self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).m_next });
        // SAFETY: MsgBlkNode is a transparent wrapper around mbuf.
        unsafe { Some(&*(ptr.as_ptr() as *const MsgBlkNode)) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { count_chain(self.curr) };
        (len, Some(len))
    }
}

impl ExactSizeIterator for MsgBlkIter<'_> {}

impl<'a> Read for MsgBlkIter<'a> {
    type Chunk = &'a [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_ref())
    }

    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

impl<'a> Iterator for MsgBlkIterMut<'a> {
    type Item = &'a mut MsgBlkNode;

    fn next(&mut self) -> Option<Self::Item> {
        let ptr = self.curr?;
        self.curr = NonNull::new(unsafe { (*ptr.as_ptr()).m_next });
        // SAFETY: MsgBlkNode is a transparent wrapper around mbuf.
        unsafe { Some(&mut *(ptr.as_ptr() as *mut MsgBlkNode)) }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = unsafe { count_chain(self.curr) };
        (len, Some(len))
    }
}

impl ExactSizeIterator for MsgBlkIterMut<'_> {}

impl<'a> Read for MsgBlkIterMut<'a> {
    type Chunk = &'a mut [u8];

    fn next_chunk(&mut self) -> ingot::types::ParseResult<Self::Chunk> {
        self.next().ok_or(IngotParseErr::TooSmall).map(|v| v.as_mut())
    }

    fn chunks_len(&self) -> usize {
        ExactSizeIterator::len(self)
    }
}

impl BufferState for MsgBlkIterMut<'_> {
    #[inline]
    fn len(&self) -> usize {
        unsafe { count_chain_bytes(self.curr) }
    }

    #[inline]
    fn base_ptr(&self) -> Option<NonNull<mbuf>> {
        self.curr
    }

    #[inline]
    fn large_offload(&self) -> bool {
        let flags = self
            .curr
            .map(|v| unsafe { typed_offload_info(v) })
            .unwrap_or_default()
            .flags;
        flags.intersects(MblkOffloadFlags::HW_LSO_FLAGS)
    }
}

impl Drop for MsgBlk {
    fn drop(&mut self) {
        free_chain(self.0.as_ptr());
    }
}

/// Free an `m_next` chain, which may be null.
fn free_chain(m: *mut mbuf) {
    if m.is_null() {
        return;
    }

    #[cfg(all(not(feature = "std"), not(test)))]
    unsafe {
        sys::m_freem(m)
    }

    #[cfg(any(feature = "std", test))]
    mock::freem(m)
}

/// Copy the bytes of `pkt` from `off` onward into a new chain of plain
/// segments, sharing cluster storage where the kernel allows.
fn copy_tail(pkt: &MsgBlk, off: usize) -> Option<NonNull<mbuf>> {
    #[cfg(all(not(feature = "std"), not(test)))]
    unsafe {
        const M_COPYALL: c_int = 1_000_000_000;
        // Starting past the header, the copy carries no packet header.
        NonNull::new(sys::m_copym(
            pkt.0.as_ptr(),
            c_int::try_from(off).ok()?,
            M_COPYALL,
            sys::M_NOWAIT,
        ))
    }

    #[cfg(any(feature = "std", test))]
    {
        let bytes = pkt.copy_all();
        let seg = MsgBlk::copy(&bytes[off..]);
        let seg = ManuallyDrop::new(seg).0;
        unsafe { mock::demote_pkthdr(seg.as_ptr()) };
        Some(seg)
    }
}

/// Allocate a single-buffer packet with room for at least `size` bytes.
/// Returns null if memory is short.
pub fn allocb(size: usize) -> *mut mbuf {
    assert!(size <= MBLK_MAX_SIZE);

    #[cfg(any(feature = "std", test))]
    return mock::alloc(size);

    #[cfg(all(not(feature = "std"), not(test)))]
    unsafe {
        kernel_alloc(size)
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
unsafe fn kernel_alloc(size: usize) -> *mut mbuf {
    use alloc::alloc::Layout;

    unsafe {
        if size <= sys::MJUM16BYTES {
            return sys::m_get3(
                size as c_int,
                sys::M_NOWAIT,
                sys::MT_DATA,
                sys::M_PKTHDR as c_int,
            );
        }

        let m =
            sys::m_get2(0, sys::M_NOWAIT, sys::MT_DATA, sys::M_PKTHDR as c_int);
        if m.is_null() {
            return m;
        }
        let Ok(layout) = Layout::from_size_align(size, LARGE_BUF_ALIGN) else {
            sys::m_freem(m);
            return ptr::null_mut();
        };
        let buf = alloc::alloc::alloc(layout);
        if buf.is_null() {
            sys::m_freem(m);
            return ptr::null_mut();
        }
        sys::m_extadd(
            m,
            buf.cast(),
            size as u32,
            Some(free_large_buf),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            sys::EXT_MOD_TYPE,
        );
        LARGE_BUFS.fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        m
    }
}

#[cfg(all(not(feature = "std"), not(test)))]
unsafe extern "C" fn free_large_buf(m: *mut mbuf) {
    use alloc::alloc::Layout;

    unsafe {
        let ext = (*m).ext();
        let layout = Layout::from_size_align_unchecked(
            ext.ext_size as usize,
            LARGE_BUF_ALIGN,
        );
        alloc::alloc::dealloc(ext.ext_buf().cast(), layout);
    }
    LARGE_BUFS.fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
}

/// A userland stand-in for the kernel's mbuf allocator, laid out exactly
/// like the real thing so the backend can be tested on any host.
#[cfg(any(feature = "std", test))]
pub(crate) mod mock {
    use super::LARGE_BUF_ALIGN;
    use super::sys;
    use super::sys::mbuf;
    use std::alloc::Layout;
    use std::ptr;

    const MBUF_LAYOUT: Layout = match Layout::from_size_align(sys::MSIZE, 8) {
        Ok(l) => l,
        Err(_) => panic!("bad mbuf layout"),
    };

    fn buf_layout(size: usize) -> Layout {
        Layout::from_size_align(size, LARGE_BUF_ALIGN).expect("buffer layout")
    }

    /// Allocate a packet header mbuf, backed by an external buffer when
    /// `size` exceeds `MHLEN`. A request for 0 bytes gets internal
    /// storage, like `m_get2`.
    pub fn alloc(size: usize) -> *mut mbuf {
        unsafe {
            let m = std::alloc::alloc_zeroed(MBUF_LAYOUT) as *mut mbuf;
            assert!(!m.is_null());
            (*m).m_type_flags = sys::MT_DATA as u32 | (sys::M_PKTHDR << 8);

            if size <= sys::MHLEN {
                (*m).m_data = (m as *mut u8).add(sys::MPKTHSIZE).cast();
            } else {
                let buf = std::alloc::alloc(buf_layout(size));
                assert!(!buf.is_null());
                let ext = (*m).ext_mut();
                ext.ext_ref.ext_count = 1;
                ext.ext_size = size as u32;
                ext.ext_type_flags =
                    sys::EXT_MOD_TYPE as u32 | (sys::EXT_FLAG_EMBREF << 8);
                ext.storage.buf.ext_buf = buf.cast();
                ext.ext_free = Some(free_buf);
                (*m).set_m_flags(sys::M_PKTHDR | sys::M_EXT);
                (*m).m_data = buf.cast();
            }
            m
        }
    }

    unsafe extern "C" fn free_buf(m: *mut mbuf) {
        unsafe {
            let ext = (*m).ext();
            std::alloc::dealloc(
                ext.ext_buf().cast(),
                buf_layout(ext.ext_size as usize),
            );
        }
    }

    /// `m_freem`: free every mbuf in an `m_next` chain.
    pub fn freem(mut m: *mut mbuf) {
        while !m.is_null() {
            unsafe {
                let next = (*m).m_next;
                if (*m).has_flags(sys::M_EXT) {
                    let ext = (*m).ext_mut();
                    ext.ext_ref.ext_count -= 1;
                    if ext.ext_ref.ext_count == 0
                        && let Some(free) = ext.ext_free
                    {
                        free(m);
                    }
                }
                std::alloc::dealloc(m.cast(), MBUF_LAYOUT);
                m = next;
            }
        }
    }

    /// `m_demote_pkthdr`.
    pub unsafe fn demote_pkthdr(m: *mut mbuf) {
        unsafe {
            let flags = (*m).m_flags();
            (*m).set_m_flags(flags & !sys::M_PKTHDR);
            ptr::write_bytes((*m).pkthdr_mut(), 0, 1);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::engine::GenericUlp;
    use crate::engine::packet::Packet;
    use crate::engine::packet::ParseError;
    use illumos_sys_hdrs::mac::MacTunType;
    use ingot::types::ParseError as IngotParseError;

    fn head(pkt: &MsgBlk) -> &mbuf {
        unsafe { &*pkt.0.as_ptr() }
    }

    fn head_mut(pkt: &mut MsgBlk) -> &mut mbuf {
        unsafe { &mut *pkt.0.as_ptr() }
    }

    /// A chain of segments holding `parts`, with a packet header only on
    /// the first, as the stack hands them over.
    fn chain(parts: &[&[u8]]) -> *mut mbuf {
        let mut segs: Vec<*mut mbuf> = parts
            .iter()
            .map(|p| ManuallyDrop::new(MsgBlk::copy(p)).0.as_ptr())
            .collect();
        for i in 1..segs.len() {
            unsafe {
                mock::demote_pkthdr(segs[i]);
                (*segs[i - 1]).m_next = segs[i];
            }
        }
        segs.remove(0)
    }

    #[test]
    fn zero_byte_packet() {
        let mut pkt = MsgBlk::new(0);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(pkt.tail_capacity(), sys::MHLEN);

        let res = Packet::parse_outbound(pkt.iter_mut(), GenericUlp {});
        match res {
            Err(ParseError::IngotError(err)) => {
                assert_eq!(err.header().as_str(), "inner_eth");
                assert_eq!(err.error(), &IngotParseError::TooSmall);
            }
            Err(e) => panic!("expected read error, got: {e:?}"),
            _ => panic!("expected failure, accidentally succeeded at parsing"),
        }

        let pkt2 = MsgBlk::copy([]);
        assert_eq!(pkt2.len(), 0);
        assert_eq!(pkt2.seg_len(), 1);
    }

    #[test]
    fn wrap() {
        let mp = chain(&[&[0x1, 0x2, 0x3, 0x4], &[0x5, 0x6]]);
        let pkt = unsafe { MsgBlk::wrap_mblk(mp).unwrap() };
        assert_eq!(pkt.seg_len(), 2);
        assert_eq!(pkt.all_segs_capacity(), sys::MHLEN + sys::MLEN);
        assert_eq!(pkt.byte_len(), 6);
    }

    #[test]
    fn wrap_rejects_packet_lists() {
        let a = ManuallyDrop::new(MsgBlk::new(8)).0.as_ptr();
        let b = ManuallyDrop::new(MsgBlk::new(8)).0.as_ptr();
        unsafe { (*a).m_nextpkt = b };
        assert!(matches!(
            unsafe { MsgBlk::wrap_mblk(a) },
            Err(WrapError::Chain)
        ));
        assert!(matches!(
            unsafe { MsgBlk::wrap_mblk(ptr::null_mut()) },
            Err(WrapError::NullPtr)
        ));
        drop(unsafe { MsgBlkChain::new(a) }.unwrap());
    }

    #[test]
    fn read_seg() {
        let mp = chain(&[&[0x1, 0x2, 0x3, 0x4], &[0x5, 0x6]]);
        let pkt = unsafe { MsgBlk::wrap_mblk(mp).unwrap() };
        assert_eq!(pkt.byte_len(), 6);
        assert_eq!(pkt.seg_len(), 2);

        let mut segs = pkt.iter();
        assert_eq!(segs.next().map(|v| &v[..]).unwrap(), &[0x1, 0x2, 0x3, 0x4]);
        assert_eq!(segs.next().map(|v| &v[..]).unwrap(), &[0x5, 0x6]);
    }

    #[test]
    fn truncate() {
        let mut p1 = MsgBlk::copy([0, 1, 2, 3]);
        p1.append(MsgBlk::copy([4, 5, 6, 7]));
        p1.append(MsgBlk::copy([8, 9, 10, 11]));

        assert_eq!(p1.seg_len(), 3);
        assert_eq!(p1.byte_len(), 12);

        p1.truncate_chain(7);
        assert_eq!(p1.seg_len(), 2);
        assert_eq!(p1.byte_len(), 7);
        let mut iter = p1.iter();
        assert_eq!(&iter.next().unwrap()[..], &[0, 1, 2, 3]);
        assert_eq!(&iter.next().unwrap()[..], &[4, 5, 6]);
    }

    #[test]
    fn uninitialized_packet() {
        let pkt = MsgBlk::new(200);
        assert_eq!(pkt.len(), 0);
        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(pkt.tail_capacity(), 200);
    }

    #[test]
    fn large_packet() {
        let pkt = MsgBlk::new(MBLK_MAX_SIZE);
        assert!(head(&pkt).has_flags(sys::M_EXT | sys::M_PKTHDR));
        assert_eq!(pkt.tail_capacity(), MBLK_MAX_SIZE);
    }

    #[test]
    fn expand_and_shrink() {
        let mut seg = MsgBlk::new(300);
        assert_eq!(seg.len(), 0);
        seg.resize(300).unwrap();
        assert_eq!(seg.len(), 300);
        seg.drop_front_bytes(4).unwrap();
        assert_eq!(seg.len(), 296);
        seg.expand_front(4).unwrap();
        assert_eq!(seg.len(), 300);

        assert!(seg.resize(302).is_err());
        assert!(seg.drop_front_bytes(302).is_err());
        assert!(seg.expand_front(4).is_err());
    }

    #[test]
    fn prefix_len() {
        let mut seg = MsgBlk::new(18);
        assert_eq!(seg.head_capacity(), 0);
        seg.resize(18).unwrap();
        assert_eq!(seg.head_capacity(), 0);
        seg.drop_front_bytes(4).unwrap();
        assert_eq!(seg.head_capacity(), 4);
        seg.expand_front(4).unwrap();
        assert_eq!(seg.head_capacity(), 0);
    }

    #[test]
    fn pop_all_then_emit_front() {
        let mut pkt = MsgBlk::new_ethernet(8);
        pkt.pop_all();
        assert_eq!(pkt.len(), 0);
        pkt.write_bytes_front([5, 6, 7, 8]).unwrap();
        pkt.write_bytes_front([1, 2, 3, 4]).unwrap();
        assert_eq!(&pkt[..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn shared_buffer_is_not_writable() {
        let mut pkt = MsgBlk::new(300);
        pkt.resize(100).unwrap();
        pkt.drop_front_bytes(10).unwrap();
        assert_eq!(pkt.ref_count(), 1);
        assert!(pkt.head_capacity() > 0 && pkt.tail_capacity() > 0);

        head_mut(&mut pkt).ext_mut().ext_ref.ext_count = 2;
        assert_eq!(pkt.ref_count(), 2);
        assert_eq!(pkt.head_capacity(), 0);
        assert_eq!(pkt.tail_capacity(), 0);
        assert!(pkt.write_bytes_front([0]).is_err());
        head_mut(&mut pkt).ext_mut().ext_ref.ext_count = 1;
    }

    #[test]
    fn read_only_buffer_is_not_writable() {
        let mut pkt = MsgBlk::new(64);
        let flags = head(&pkt).m_flags();
        head_mut(&mut pkt).set_m_flags(flags | sys::M_RDONLY);
        assert!(pkt.ref_count() > 1);
        assert_eq!(pkt.tail_capacity(), 0);
        assert!(pkt.write_bytes_back([0]).is_err());
    }

    #[test]
    fn append_moves_flow_metadata() {
        let mut hdr = MsgBlk::new(16);
        let mut body = MsgBlk::copy([1, 2, 3]);
        let rcvif = 0x1000 as *mut core::ffi::c_void;
        {
            let ph = head_mut(&mut body).pkthdr_mut();
            ph.flowid = 7;
            ph.rsstype = 3;
            ph.rcvif = rcvif;
        }
        hdr.append(body);

        assert_eq!(hdr.seg_len(), 2);
        assert_eq!(head(&hdr).pkthdr().flowid, 7);
        assert_eq!(head(&hdr).pkthdr().rsstype, 3);
        assert_eq!(head(&hdr).pkthdr().rcvif, rcvif);
        let second = hdr.iter().nth(1).unwrap();
        assert!(!second.0.has_flags(sys::M_PKTHDR));
        assert_eq!(&second[..], &[1, 2, 3]);
    }

    #[test]
    fn append_keeps_existing_flow_metadata() {
        let mut pkt = MsgBlk::copy([0, 1]);
        head_mut(&mut pkt).pkthdr_mut().flowid = 11;
        pkt.append(MsgBlk::copy([2, 3]));
        assert_eq!(head(&pkt).pkthdr().flowid, 11);
    }

    #[test]
    fn unwrap_sets_pkthdr_len() {
        let mut pkt = MsgBlk::copy([0, 1, 2, 3]);
        pkt.append(MsgBlk::copy([4, 5, 6]));
        let mp = pkt.unwrap_mblk();
        assert_eq!(unsafe { (*mp.as_ptr()).pkthdr().len }, 7);
        drop(unsafe { MsgBlk::wrap_mblk(mp.as_ptr()) });
    }

    #[test]
    fn drop_empty_segments_copies_plain_segment() {
        let mut pkt = MsgBlk::new(0);
        head_mut(&mut pkt).pkthdr_mut().flowid = 9;
        pkt.request_offload(MblkOffloadFlags::HCK_FULLCKSUM, 0);
        pkt.append(MsgBlk::copy([1, 2, 3]));

        pkt.drop_empty_segments();

        assert_eq!(pkt.seg_len(), 1);
        assert_eq!(&pkt[..], &[1, 2, 3]);
        assert!(head(&pkt).has_flags(sys::M_PKTHDR));
        assert_eq!(head(&pkt).pkthdr().flowid, 9);
        assert!(
            pkt.offload_flags().flags.contains(MblkOffloadFlags::HCK_FULLCKSUM)
        );
    }

    #[test]
    fn drop_empty_segments_reuses_external_segment() {
        let mut pkt = MsgBlk::new(0);
        let body = MsgBlk::copy([7u8; 300]);
        let body_ptr = body.0.as_ptr();
        pkt.append(body);
        pkt.append(MsgBlk::copy([8]));

        pkt.drop_empty_segments();

        assert_eq!(pkt.0.as_ptr(), body_ptr);
        assert!(head(&pkt).has_flags(sys::M_PKTHDR));
        assert_eq!(pkt.seg_len(), 2);
        assert_eq!(pkt.byte_len(), 301);
    }

    #[test]
    fn pullup_partial() {
        let mp = chain(&[&[0, 1, 2, 3], &[4, 5, 6, 7], &[8, 9, 10, 11]]);
        let pkt = unsafe { MsgBlk::wrap_mblk(mp).unwrap() };

        let up = pkt.pullup(NonZeroUsize::new(6)).unwrap();
        assert_eq!(&up[..], &[0, 1, 2, 3, 4, 5]);
        assert_eq!(up.copy_all(), pkt.copy_all());
        assert_eq!(pkt.seg_len(), 3);

        let all = pkt.pullup(None).unwrap();
        assert_eq!(all.seg_len(), 1);
        assert_eq!(all.copy_all(), pkt.copy_all());

        assert_eq!(
            pkt.pullup(NonZeroUsize::new(13)).unwrap_err(),
            PktPullupError::TooLong
        );
    }

    #[test]
    fn import_rx_offload_replaces_scratch() {
        let mut pkt = MsgBlk::new(64);
        {
            let ph = head_mut(&mut pkt).pkthdr_mut();
            ph.ph_loc.ph_loc = sys::ph_scratch { sixtyfour: [u64::MAX] };
            ph.csum_flags = sys::CSUM_L3_CALC
                | sys::CSUM_L3_VALID
                | sys::CSUM_L4_CALC
                | sys::CSUM_L4_VALID;
        }
        pkt.import_rx_offload();

        let info = pkt.offload_flags();
        assert_eq!(
            info.flags,
            MblkOffloadFlags::HCK_IPV4_HDRCKSUM_OK
                | MblkOffloadFlags::HCK_FULLCKSUM_OK
        );
        assert_eq!(info.mss, 0);
    }

    #[test]
    fn request_offload_round_trips() {
        let mut pkt = MsgBlk::new(64);
        pkt.request_offload(
            MblkOffloadFlags::HCK_INNER_FULL | MblkOffloadFlags::HW_LSO,
            1448,
        );
        let info = pkt.offload_flags();
        assert!(info.flags.contains(MblkOffloadFlags::HCK_INNER_FULL));
        assert!(info.flags.contains(MblkOffloadFlags::HW_LSO));
        assert_eq!(info.mss, 1448);
        assert!(pkt.iter_mut().large_offload());

        let mut other = MsgBlk::new(8);
        pkt.copy_offload_info_to(&mut other);
        assert_eq!(other.offload_flags().mss, 1448);
    }

    #[test]
    fn fill_parse_info_records_lengths() {
        let mut pkt = MsgBlk::new(64);
        let outer = mac_ether_offload_info_t {
            meoi_tuntype: MacTunType::GENEVE,
            meoi_l2hlen: 14,
            meoi_l3hlen: 40,
            meoi_l4hlen: 8,
            meoi_tunhlen: 8,
            ..Default::default()
        };
        let inner = mac_ether_offload_info_t {
            meoi_l2hlen: 14,
            meoi_l3hlen: 20,
            meoi_l4hlen: 20,
            ..Default::default()
        };
        pkt.fill_parse_info(&outer, Some(&inner)).unwrap();

        let ph = head(&pkt).pkthdr();
        let lens = ph.hdrlens();
        assert_eq!(
            (lens.l2hlen, lens.l3hlen, lens.l4hlen, lens.l5hlen),
            (14, 40, 8, 8)
        );
        assert_eq!(
            (lens.inner_l2hlen, lens.inner_l3hlen, lens.inner_l4hlen),
            (14, 20, 20)
        );
        assert_eq!(ph.csum_flags, 0);
    }

    #[test]
    fn test_long_packet_continuation() {
        const N_SEGMENTS: usize = 8;
        let parts = [[0u8; 32]; N_SEGMENTS];
        let refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        let mp = chain(&refs);

        let mut expected = Vec::new();
        let mut curr = mp;
        while !curr.is_null() {
            expected.push(curr);
            curr = unsafe { (*curr).m_next };
        }

        let packet = unsafe { MsgBlk::wrap_mblk(mp) }
            .expect("Failed to wrap mbuf chain with many segments");
        assert_eq!(packet.seg_len(), N_SEGMENTS);
        for (seg, m) in packet.iter().zip(expected) {
            assert_eq!(core::ptr::addr_of!(seg.0) as *mut mbuf, m);
        }
    }

    fn create_linked_pkts(n: usize) -> Vec<*mut mbuf> {
        let els: Vec<*mut mbuf> = (0..n).map(|_| allocb(8)).collect();
        for (lhs, rhs) in els.iter().zip(els[1..].iter()) {
            unsafe { (**lhs).m_nextpkt = *rhs };
        }
        els
    }

    #[test]
    fn chain_has_correct_ends() {
        let els = create_linked_pkts(3);
        let chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();
        let inner = chain.0.as_ref().unwrap();
        assert_eq!(inner.head.as_ptr(), els[0]);
        assert_eq!(inner.tail.as_ptr(), els[2]);
    }

    #[test]
    fn chain_breaks_links() {
        let els = create_linked_pkts(3);
        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();

        let p0 = chain.pop_front().unwrap();
        assert_eq!(p0.mblk_addr(), els[0] as uintptr_t);
        unsafe { assert!((*els[0]).m_nextpkt.is_null()) };

        let inner = chain.0.as_ref().unwrap();
        assert_eq!(inner.head.as_ptr(), els[1]);
        assert_eq!(inner.tail.as_ptr(), els[2]);
        unsafe { assert!((*els[2]).m_nextpkt.is_null()) };
    }

    #[test]
    fn chain_append_links() {
        let els = create_linked_pkts(3);
        let new_el = allocb(8);

        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();
        chain.append(unsafe { MsgBlk::wrap_mblk(new_el) }.unwrap());

        let inner = chain.0.as_ref().unwrap();
        assert_eq!(inner.head.as_ptr(), els[0]);
        assert_eq!(inner.tail.as_ptr(), new_el);
        unsafe {
            assert!((*new_el).m_nextpkt.is_null());
            assert_eq!((*els[2]).m_nextpkt, new_el);
        }
    }

    #[test]
    fn chain_drain_complete() {
        let els = create_linked_pkts(64);
        let mut chain = unsafe { MsgBlkChain::new(els[0]) }.unwrap();
        for el in els {
            assert_eq!(chain.pop_front().unwrap().mblk_addr(), el as uintptr_t);
        }
        assert!(chain.pop_front().is_none());
    }
}
