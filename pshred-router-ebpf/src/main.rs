#![no_std]
#![no_main]

//! XDP pshred demultiplexer.
//!
//! Reads the proposer index `j` from the pshred header in the UDP payload and
//! redirects the frame into an `XSKMAP` slot keyed by `j`. Userspace binds one
//! AF_XDP socket per proposer (sharing a single UMEM on one RX queue), so each
//! proposer's pshreds land in their own ring with no per-packet syscall.
//!
//! Action policy:
//!   * non-IPv4 / non-UDP / wrong port / short frame -> XDP_PASS (not ours)
//!   * Eq.(1) violation                              -> XDP_DROP (+counter)
//!   * proposer out of range (j == 0 or j > p)       -> XDP_DROP (+counter)
//!   * valid pshred, socket bound at j               -> XDP_REDIRECT
//!   * valid pshred, no socket bound at j            -> XDP_PASS (don't blackhole)

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{PerCpuArray, XskMap},
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};
use pshred_router_common::{
    stats, validate_cycle_bounds, MAX_PROPOSERS, OFF_CYCLE, OFF_PROPOSER, OFF_PSLICE,
    PSHRED_FIXED_LEN, PSHRED_UDP_PORT,
};

/// One AF_XDP socket slot per proposer. Keyed by proposer index `j` (1-indexed),
/// so we size for `MAX_PROPOSERS + 1` and leave slot 0 unused.
#[map]
static XSKS: XskMap = XskMap::with_max_entries(MAX_PROPOSERS as u32 + 1, 0);

// Per-CPU stat counters; indices defined in `pshred_router_common::stats`.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stats::COUNT, 0);

#[xdp]
pub fn pshred_router(ctx: XdpContext) -> u32 {
    try_pshred_router(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

#[inline(always)]
fn bump(idx: u32) {
    if let Some(v) = STATS.get_ptr_mut(idx) {
        unsafe { *v += 1 };
    }
}

/// Bounds-checked pointer into the packet. `Err(())` means the read would run
/// past `data_end`; callers translate that into XDP_PASS, since a short or
/// malformed frame is not a pshred we own.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn read_u16_le(ctx: &XdpContext, offset: usize) -> Result<u16, ()> {
    let p = ptr_at::<[u8; 2]>(ctx, offset)?;
    Ok(u16::from_le_bytes(unsafe { *p }))
}

#[inline(always)]
fn read_u64_le(ctx: &XdpContext, offset: usize) -> Result<u64, ()> {
    let p = ptr_at::<[u8; 8]>(ctx, offset)?;
    Ok(u64::from_le_bytes(unsafe { *p }))
}

fn try_pshred_router(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *const EthHdr = ptr_at(ctx, 0)?;
    if !matches!(unsafe { (*eth).ether_type() }, Ok(EtherType::Ipv4)) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    if unsafe { (*ip).version() } != 4 {
        return Ok(xdp_action::XDP_PASS);
    }
    if !matches!(unsafe { (*ip).proto() }, Ok(IpProto::Udp)) {
        return Ok(xdp_action::XDP_PASS);
    }

    // Honour the IHL: with IPv4 options the header is longer than 20 bytes, so
    // the UDP header is not at a fixed offset. `ihl()` returns the header length
    // in bytes; reject anything below the 20-byte minimum as malformed. (VLAN-
    // tagged frames are out of scope: the EtherType check above only matches
    // untagged IPv4.)
    let ihl = unsafe { (*ip).ihl() } as usize;
    if ihl < Ipv4Hdr::LEN {
        return Ok(xdp_action::XDP_PASS);
    }
    let udp_off = EthHdr::LEN + ihl;
    let udp: *const UdpHdr = ptr_at(ctx, udp_off)?;
    // dst_port() already converts network -> host byte order.
    if unsafe { (*udp).dst_port() } != PSHRED_UDP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload = udp_off + UdpHdr::LEN;

    // Require a complete fixed header before we treat this as a pshred.
    if ptr_at::<[u8; PSHRED_FIXED_LEN]>(ctx, payload).is_err() {
        return Ok(xdp_action::XDP_PASS);
    }
    bump(stats::TOTAL);

    let proposer = read_u16_le(ctx, payload + OFF_PROPOSER)?;
    let cycle = read_u64_le(ctx, payload + OFF_CYCLE)?;
    let pslice = read_u64_le(ctx, payload + OFF_PSLICE)?;

    if !validate_cycle_bounds(cycle, pslice) {
        bump(stats::EQ1_DROP);
        return Ok(xdp_action::XDP_DROP);
    }

    // proposer index is 1-indexed: 1 <= j <= p
    if proposer == 0 || proposer > MAX_PROPOSERS {
        bump(stats::RANGE_DROP);
        return Ok(xdp_action::XDP_DROP);
    }

    // Demux: redirect into this proposer's AF_XDP socket. The low bits of the
    // flags argument are the action the kernel returns when the XSKMAP slot is
    // empty, so we pass XDP_PASS: an unbound proposer's frame is handed back to
    // the stack rather than blackholed. `redirect` returns Ok(XDP_REDIRECT) on a
    // hit and Err(XDP_PASS) on a miss, so the two arms split cleanly.
    match XSKS.redirect(proposer as u32, xdp_action::XDP_PASS as u64) {
        Ok(action) => {
            bump(stats::REDIRECTED);
            Ok(action)
        }
        Err(_) => {
            bump(stats::NO_SOCKET);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
