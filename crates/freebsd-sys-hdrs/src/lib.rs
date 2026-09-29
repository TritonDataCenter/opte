// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2026 Edgecast Cloud LLC.

//! FreeBSD kernel types used by OPTE's mbuf packet backend.
//!
//! The layouts mirror `sys/sys/mbuf.h` on LP64 and are checked against
//! the sizes the kernel itself asserts in `sys/kern/uipc_mbuf.c`.

#![no_std]
#![allow(non_camel_case_types)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("freebsd-sys-hdrs only describes the LP64 mbuf layout");

use core::ffi::c_char;
use core::ffi::c_int;
use core::ffi::c_short;
use core::ffi::c_uint;
use core::ffi::c_void;
use core::mem::offset_of;
use core::mem::size_of;
use core::ptr;

pub const MSIZE: usize = 256;
pub const MHSIZE: usize = offset_of!(mbuf, m_u);
pub const MPKTHSIZE: usize = MHSIZE + size_of::<pkthdr>();
pub const MLEN: usize = MSIZE - MHSIZE;
pub const MHLEN: usize = MSIZE - MPKTHSIZE;
pub const MCLBYTES: usize = 2048;
pub const MJUMPAGESIZE: usize = 4096;
pub const MJUM9BYTES: usize = 9 * 1024;
pub const MJUM16BYTES: usize = 16 * 1024;

pub const M_NOWAIT: c_int = 0x0001;
pub const MT_DATA: c_short = 1;

pub const M_EXT: u32 = 0x0000_0001;
pub const M_PKTHDR: u32 = 0x0000_0002;
pub const M_EOR: u32 = 0x0000_0004;
pub const M_RDONLY: u32 = 0x0000_0008;
pub const M_EXTPG: u32 = 0x0000_0100;
pub const M_NOFREE: u32 = 0x0000_0200;

pub const EXT_NET_DRV: c_int = 252;
pub const EXT_MOD_TYPE: c_int = 253;
pub const EXT_EXTREF: u32 = 255;
pub const EXT_FLAG_EMBREF: u32 = 0x00_0001;

pub const CSUM_IP: u32 = 0x0000_0001;
pub const CSUM_IP_UDP: u32 = 0x0000_0002;
pub const CSUM_IP_TCP: u32 = 0x0000_0004;
pub const CSUM_IP_SCTP: u32 = 0x0000_0008;
pub const CSUM_IP_TSO: u32 = 0x0000_0010;
pub const CSUM_INNER_IP6_UDP: u32 = 0x0000_0040;
pub const CSUM_INNER_IP6_TCP: u32 = 0x0000_0080;
pub const CSUM_INNER_IP6_TSO: u32 = 0x0000_0100;
pub const CSUM_IP6_UDP: u32 = 0x0000_0200;
pub const CSUM_IP6_TCP: u32 = 0x0000_0400;
pub const CSUM_IP6_SCTP: u32 = 0x0000_0800;
pub const CSUM_IP6_TSO: u32 = 0x0000_1000;
pub const CSUM_INNER_IP: u32 = 0x0000_4000;
pub const CSUM_INNER_IP_UDP: u32 = 0x0000_8000;
pub const CSUM_INNER_IP_TCP: u32 = 0x0001_0000;
pub const CSUM_INNER_IP_TSO: u32 = 0x0002_0000;
pub const CSUM_ENCAP_VXLAN: u32 = 0x0004_0000;
/// FreeBSD 16 and later; reserved in 15.
pub const CSUM_ENCAP_GENEVE: u32 = 0x0008_0000;
pub const CSUM_INNER_L3_CALC: u32 = 0x0010_0000;
pub const CSUM_INNER_L3_VALID: u32 = 0x0020_0000;
pub const CSUM_INNER_L4_CALC: u32 = 0x0040_0000;
pub const CSUM_INNER_L4_VALID: u32 = 0x0080_0000;
pub const CSUM_L3_CALC: u32 = 0x0100_0000;
pub const CSUM_L3_VALID: u32 = 0x0200_0000;
pub const CSUM_L4_CALC: u32 = 0x0400_0000;
pub const CSUM_L4_VALID: u32 = 0x0800_0000;
pub const CSUM_SND_TAG: u32 = 0x8000_0000;

pub type m_ext_free_t = unsafe extern "C" fn(*mut mbuf);

/// `PH_per` and `PH_loc` scratch space.
#[repr(C)]
#[derive(Clone, Copy)]
pub union ph_scratch {
    pub eight: [u8; 8],
    pub sixteen: [u16; 4],
    pub thirtytwo: [u32; 2],
    pub sixtyfour: [u64; 1],
    pub ptr: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct pkthdr_hdrlens {
    pub l2hlen: u8,
    pub l3hlen: u8,
    pub l4hlen: u8,
    pub l5hlen: u8,
    pub inner_l2hlen: u8,
    pub inner_l3hlen: u8,
    pub inner_l4hlen: u8,
    pub inner_l5hlen: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union pkthdr_lens {
    pub rcv_tstmp: u64,
    pub lens: pkthdr_hdrlens,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union pkthdr_loc {
    pub ph_loc: ph_scratch,
    pub memlen: c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct pkthdr {
    /// Union of `snd_tag`, `rcvif` and `rcvidx`/`rcvgen`.
    pub rcvif: *mut c_void,
    /// Union of `leaf_rcvif` and `leaf_rcvidx`/`leaf_rcvgen`.
    pub leaf_rcvif: *mut c_void,
    /// `SLIST_HEAD(packet_tags, m_tag)`.
    pub tags: *mut c_void,
    pub len: i32,
    pub flowid: u32,
    pub csum_flags: u32,
    pub fibnum: u16,
    pub numa_domain: u8,
    pub rsstype: u8,
    pub hdr: pkthdr_lens,
    pub ph_per: ph_scratch,
    pub ph_loc: pkthdr_loc,
}

impl pkthdr {
    /// `m_pkthdr.tso_segsz`.
    pub fn tso_segsz(&self) -> u16 {
        unsafe { self.ph_per.sixteen[1] }
    }

    pub fn set_tso_segsz(&mut self, v: u16) {
        unsafe { self.ph_per.sixteen[1] = v }
    }

    /// `m_pkthdr.ether_vtag`.
    pub fn ether_vtag(&self) -> u16 {
        unsafe { self.ph_per.sixteen[0] }
    }

    pub fn hdrlens(&self) -> pkthdr_hdrlens {
        unsafe { self.hdr.lens }
    }

    pub fn set_hdrlens(&mut self, lens: pkthdr_hdrlens) {
        self.hdr.lens = lens;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ext_ref {
    pub ext_count: c_uint,
    pub ext_cnt: *mut c_uint,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ext_buf_args {
    pub ext_buf: *mut c_char,
    pub ext_arg2: *mut c_void,
}

/// The regular external buffer, overlaid with the `M_EXTPG` page vector.
#[repr(C)]
#[derive(Clone, Copy)]
pub union ext_storage {
    pub buf: ext_buf_args,
    pub _extpg: [u64; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct m_ext {
    pub ext_ref: ext_ref,
    pub ext_size: u32,
    /// `ext_type:8` in the low bits, `ext_flags:24` above.
    pub ext_type_flags: u32,
    pub storage: ext_storage,
    pub ext_free: Option<m_ext_free_t>,
    pub ext_arg1: *mut c_void,
}

impl m_ext {
    pub fn ext_type(&self) -> u32 {
        self.ext_type_flags & 0xff
    }

    pub fn ext_flags(&self) -> u32 {
        self.ext_type_flags >> 8
    }

    pub fn ext_buf(&self) -> *mut c_char {
        unsafe { self.storage.buf.ext_buf }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct mbuf_hdr_ext {
    pub m_pkthdr: pkthdr,
    /// Overlaid by `m_pktdat` when `M_EXT` is clear.
    pub m_ext: m_ext,
}

#[repr(C)]
pub union mbuf_u {
    pub s: mbuf_hdr_ext,
    pub m_dat: [u8; MSIZE - 32],
}

#[repr(C)]
pub struct mbuf {
    pub m_next: *mut mbuf,
    pub m_nextpkt: *mut mbuf,
    pub m_data: *mut c_char,
    pub m_len: i32,
    /// `m_type:8` in the low bits, `m_flags:24` above.
    pub m_type_flags: u32,
    pub m_u: mbuf_u,
}

const _: () = {
    assert!(MHSIZE == 32);
    assert!(size_of::<pkthdr>() == 64);
    assert!(size_of::<m_ext>() == 160);
    assert!(size_of::<mbuf>() == MSIZE);
    assert!(MPKTHSIZE == 96);
    assert!(offset_of!(pkthdr, len) == 24);
    assert!(offset_of!(pkthdr, csum_flags) == 32);
    assert!(offset_of!(pkthdr, hdr) == 40);
    assert!(offset_of!(pkthdr, ph_per) == 48);
    assert!(offset_of!(m_ext, storage) == 16);
    assert!(offset_of!(m_ext, ext_free) == 144);
};

impl mbuf {
    pub fn m_type(&self) -> u32 {
        self.m_type_flags & 0xff
    }

    pub fn m_flags(&self) -> u32 {
        self.m_type_flags >> 8
    }

    pub fn set_m_flags(&mut self, flags: u32) {
        self.m_type_flags = (self.m_type_flags & 0xff) | (flags << 8);
    }

    pub fn has_flags(&self, flags: u32) -> bool {
        self.m_flags() & flags == flags
    }

    /// `m_pkthdr`, valid only when `M_PKTHDR` is set.
    pub fn pkthdr(&self) -> &pkthdr {
        unsafe { &self.m_u.s.m_pkthdr }
    }

    pub fn pkthdr_mut(&mut self) -> &mut pkthdr {
        unsafe { &mut self.m_u.s.m_pkthdr }
    }

    /// `m_ext`, valid only when `M_EXT` is set.
    pub fn ext(&self) -> &m_ext {
        unsafe { &self.m_u.s.m_ext }
    }

    pub fn ext_mut(&mut self) -> &mut m_ext {
        unsafe { &mut self.m_u.s.m_ext }
    }
}

/// `M_START(m)`: the first byte of the mbuf's storage, or null for an
/// unmapped `M_EXTPG` mbuf.
///
/// # Safety
/// `m` must point to a valid mbuf.
pub unsafe fn m_start(m: *const mbuf) -> *mut c_char {
    unsafe {
        let flags = (*m).m_flags();
        if flags & M_EXTPG != 0 {
            ptr::null_mut()
        } else if flags & M_EXT != 0 {
            (*m).ext().ext_buf()
        } else if flags & M_PKTHDR != 0 {
            (m as *mut c_char).add(MPKTHSIZE)
        } else {
            (m as *mut c_char).add(MHSIZE)
        }
    }
}

/// `M_SIZE(m)`.
///
/// # Safety
/// `m` must point to a valid mbuf.
pub unsafe fn m_size(m: *const mbuf) -> usize {
    unsafe {
        let flags = (*m).m_flags();
        if flags & M_EXT != 0 {
            (*m).ext().ext_size as usize
        } else if flags & M_PKTHDR != 0 {
            MHLEN
        } else {
            MLEN
        }
    }
}

/// `m_extrefcnt(m)`.
///
/// # Safety
/// `m` must point to a valid mbuf with `M_EXT` set.
pub unsafe fn m_extrefcnt(m: *const mbuf) -> c_uint {
    unsafe {
        let ext = (*m).ext();
        if ext.ext_flags() & EXT_FLAG_EMBREF != 0 {
            ptr::read_volatile(&raw const ext.ext_ref.ext_count)
        } else {
            ptr::read_volatile(ext.ext_ref.ext_cnt)
        }
    }
}

/// `M_WRITABLE(m)`.
///
/// # Safety
/// `m` must point to a valid mbuf.
pub unsafe fn m_writable(m: *const mbuf) -> bool {
    unsafe {
        let flags = (*m).m_flags();
        flags & (M_RDONLY | M_EXTPG) == 0
            && (flags & M_EXT == 0 || m_extrefcnt(m) == 1)
    }
}

/// `M_LEADINGSPACE(m)`.
///
/// # Safety
/// `m` must point to a valid mbuf.
pub unsafe fn m_leadingspace(m: *const mbuf) -> usize {
    unsafe {
        if !m_writable(m) {
            return 0;
        }
        (*m).m_data.offset_from(m_start(m)) as usize
    }
}

/// `M_TRAILINGSPACE(m)`.
///
/// # Safety
/// `m` must point to a valid mbuf.
pub unsafe fn m_trailingspace(m: *const mbuf) -> usize {
    unsafe {
        if !m_writable(m) {
            return 0;
        }
        let end = m_start(m).add(m_size(m));
        let used = (*m).m_data.add((*m).m_len as usize);
        end.offset_from(used) as usize
    }
}

#[cfg(feature = "kernel")]
unsafe extern "C" {
    pub fn m_get2(
        size: c_int,
        how: c_int,
        type_: c_short,
        flags: c_int,
    ) -> *mut mbuf;
    /// Like `m_get2`, but up to `MJUM16BYTES`.
    pub fn m_get3(
        size: c_int,
        how: c_int,
        type_: c_short,
        flags: c_int,
    ) -> *mut mbuf;
    pub fn m_freem(m: *mut mbuf);
    pub fn m_copym(
        m: *mut mbuf,
        off: c_int,
        len: c_int,
        wait: c_int,
    ) -> *mut mbuf;
    pub fn m_extadd(
        mb: *mut mbuf,
        buf: *mut c_char,
        size: c_uint,
        freef: Option<m_ext_free_t>,
        arg1: *mut c_void,
        arg2: *mut c_void,
        flags: c_int,
        type_: c_int,
    );
    pub fn m_demote_pkthdr(m: *mut mbuf);
}
