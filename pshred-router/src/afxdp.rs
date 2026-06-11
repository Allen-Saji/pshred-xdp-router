//! Per-proposer AF_XDP receive path.
//!
//! All proposer sockets share a single UMEM on one RX queue. An owner socket
//! holds the shared fill/completion ring; each proposer socket binds with
//! `XDP_BIND_SHARED_UMEM` and is registered in the `XSKS` map at its proposer
//! index. The kernel `bpf_redirect_map` then lands each proposer's frames in
//! that proposer's own ring, so the hot path has no per-packet syscall.

use std::{
    borrow::Borrow,
    num::NonZeroU32,
    ptr::NonNull,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as _, Result};
use aya::maps::{MapData, PerCpuArray, XskMap};
use log::{info, warn};
use pshred_router_common::MAX_PROPOSERS;
use xdpilone::{IfInfo, RingRx, Socket, SocketConfig, Umem, UmemConfig, User};

use crate::{stats, RUNNING};

/// UMEM frame size in bytes (the default chunk; pshreds are ~200 B).
const FRAME_SIZE: u64 = 1 << 12; // 4096
/// Frames in the UMEM pool. Must exceed the buffers in flight (fill + RX rings).
/// 16384 * 4096 = 64 MiB.
const NUM_FRAMES: u64 = 1 << 14;
/// Shared fill-ring depth, and the number of buffers primed into it. Kept larger
/// than a single RX ring so the pool cannot starve even when an RX ring is full
/// and briefly undrained; a 2048/2048 sizing throttled delivery under load.
const FILL_SIZE: u32 = 1 << 13; // 8192
/// Per-proposer RX ring depth.
const RX_SIZE: u32 = 1 << 12; // 4096
/// Descriptors drained from one RX ring per pass; sized to empty it in one pass.
const RX_BATCH: u32 = RX_SIZE;

/// One proposer's AF_XDP socket. Holding `User` and `RingRx` keeps the socket
/// fd open, which keeps its `XSKS` map entry valid.
struct Proposer {
    _user: User,
    rx: RingRx,
    pkts: u64,
    bytes: u64,
}

/// Map an `xdpilone` error into `anyhow` with the failing operation as context.
fn xe<T>(r: std::result::Result<T, xdpilone::Errno>, what: &str) -> Result<T> {
    r.map_err(|e| anyhow!("{what}: {e:?}"))
}

/// Bind the per-proposer sockets and drain their rings until Ctrl-C or the
/// optional duration elapses.
pub fn run(ebpf: &mut aya::Ebpf, iface: &str, duration: Option<u64>) -> Result<()> {
    // Page-aligned UMEM region on the heap (xdpilone requires page alignment).
    let area_len = (NUM_FRAMES * FRAME_SIZE) as usize;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let layout = std::alloc::Layout::from_size_align(area_len, page).unwrap();
    let mem = unsafe { std::alloc::alloc_zeroed(layout) };
    let area = NonNull::new(std::ptr::slice_from_raw_parts_mut(mem, area_len))
        .context("UMEM allocation failed")?;
    // Safety: page-aligned, sized, and intentionally leaked (lives for the run).
    let umem_cfg = UmemConfig {
        fill_size: FILL_SIZE,
        ..UmemConfig::default()
    };
    let umem = xe(unsafe { Umem::new(umem_cfg, area) }, "Umem::new")?;

    let mut info = IfInfo::invalid();
    let cname = std::ffi::CString::new(iface).unwrap();
    xe(info.from_name(cname.as_c_str()), "IfInfo::from_name")?;
    info.set_queue(0);

    // Owner socket: its fd is the UMEM fd, so it binds non-shared and forces copy
    // mode (veth / generic XDP has no zero-copy). That bind establishes the copy
    // mode of the shared buffer pool the proposer sockets then inherit.
    let owner_flags = SocketConfig::XDP_BIND_COPY;
    // Proposer sockets share the owner's UMEM. xdpilone ORs XDP_BIND_SHARED_UMEM
    // into their bind flags, and the kernel rejects SHARED_UMEM combined with
    // COPY or ZEROCOPY (EINVAL), so their own flags must be empty. They take the
    // copy/zero-copy mode from the pool the owner set up.
    let shared_flags: u16 = 0;

    // Owner socket: shares the umem fd and owns the single fill/completion ring
    // for (iface, queue 0). It is never placed in the XSKS map, so it receives
    // nothing; it exists to establish the shared fill ring the proposer sockets
    // draw their RX buffers from.
    let owner = xe(Socket::with_shared(&info, &umem), "Socket::with_shared")?;
    let mut device = xe(umem.fq_cq(&owner), "Umem::fq_cq")?;
    let owner_cfg = SocketConfig {
        rx_size: None,
        tx_size: NonZeroU32::new(64),
        bind_flags: owner_flags,
    };
    let owner_user = xe(umem.rx_tx(&owner, &owner_cfg), "rx_tx(owner)")?;
    xe(umem.bind(&owner_user), "bind(owner)")?;

    // One RX socket per proposer, bound with XDP_BIND_SHARED_UMEM and registered
    // in the XSKS map at key = proposer index.
    let rx_cfg = SocketConfig {
        rx_size: NonZeroU32::new(RX_SIZE),
        tx_size: None,
        bind_flags: shared_flags,
    };
    let mut xsks: XskMap<_> =
        XskMap::try_from(ebpf.take_map("XSKS").context("XSKS map not found")?)?;
    let mut proposers: Vec<Proposer> = Vec::with_capacity(MAX_PROPOSERS as usize);
    for j in 1..=MAX_PROPOSERS {
        let sk = xe(Socket::new(&info), "Socket::new")?;
        let user = xe(umem.rx_tx(&sk, &rx_cfg), "rx_tx(proposer)")?;
        let rx = xe(user.map_rx(), "map_rx")?;
        xe(umem.bind(&user), "bind(proposer)")?;
        xsks.set(j as u32, rx.as_raw_fd(), 0)
            .with_context(|| format!("XSKS.set({j})"))?;
        proposers.push(Proposer {
            _user: user,
            rx,
            pkts: 0,
            bytes: 0,
        });
    }
    info!(
        "bound {} proposer AF_XDP sockets on {} queue 0 (shared umem)",
        proposers.len(),
        iface
    );

    // Prime the shared fill ring so the kernel has buffers to place RX frames in.
    let fill_n = FILL_SIZE.min(NUM_FRAMES as u32);
    {
        let mut fill = device.fill(fill_n);
        let inserted = fill.insert((0..fill_n as u64).map(|i| i * FRAME_SIZE));
        fill.commit();
        if inserted < fill_n {
            warn!("only primed {inserted}/{fill_n} fill frames");
        }
    }

    let stats_map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.map("STATS").context("STATS map not found")?)?;

    // Block on the RX rings with poll(2) and drain each readable ring until it is
    // empty. poll sleeps the thread in the kernel while idle, so the loop costs
    // nothing at rest and wakes only when a ring has frames; the inner drain then
    // amortizes a burst of packets across one wakeup instead of one syscall each.
    // POLL_TIMEOUT bounds how often an idle loop re-checks RUNNING and the
    // duration.
    //
    // Note on copy-mode interfaces (veth, generic XDP): there is no DMA, so the
    // kernel only moves frames into the RX ring while userspace is actively
    // polling it. A driver with native XDP and zero-copy fills the ring from
    // hardware independently, which is where poll-and-sleep turns into a real CPU
    // saving over a per-packet recv() loop.
    const POLL_TIMEOUT_MS: libc::c_int = 250;
    let mut pfds: Vec<libc::pollfd> = proposers
        .iter()
        .map(|p| libc::pollfd {
            fd: p.rx.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();

    info!("draining per-proposer rings; Ctrl-C to stop");
    let start = Instant::now();
    let mut last_report = Instant::now();
    let mut recycle: Vec<u64> = Vec::with_capacity((RX_BATCH as usize) * proposers.len());

    while RUNNING.load(Ordering::SeqCst) {
        for pfd in pfds.iter_mut() {
            pfd.revents = 0;
        }
        let n = unsafe {
            libc::poll(
                pfds.as_mut_ptr(),
                pfds.len() as libc::nfds_t,
                POLL_TIMEOUT_MS,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue; // interrupted by SIGINT; the loop condition re-checks RUNNING
            }
            return Err(anyhow!("poll: {err}"));
        }

        // Drain every ring until a full pass comes up empty, recycling each frame
        // back into the shared fill ring as it is read. A poll timeout (n == 0)
        // reads nothing and falls through to the RUNNING/duration checks below.
        let mut got = 1u32;
        while got > 0 {
            got = 0;
            recycle.clear();
            for p in proposers.iter_mut() {
                let mut reader = p.rx.receive(RX_BATCH);
                while let Some(desc) = reader.read() {
                    p.pkts += 1;
                    p.bytes += desc.len as u64;
                    // Recycle the frame by aligning its address down to its base.
                    recycle.push(desc.addr & !(FRAME_SIZE - 1));
                    got += 1;
                }
                reader.release();
            }
            if !recycle.is_empty() {
                {
                    let mut fill = device.fill(recycle.len() as u32);
                    fill.insert(recycle.iter().copied());
                    fill.commit();
                } // drop `fill` to release the &mut device borrow before waking
                if device.needs_wakeup() {
                    device.wake();
                }
            }
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }
        }

        if last_report.elapsed() >= Duration::from_secs(1) {
            report(&proposers, &stats_map);
            last_report = Instant::now();
        }
        if duration.is_some_and(|d| start.elapsed().as_secs() >= d) {
            break;
        }
    }

    info!("final:");
    report(&proposers, &stats_map);
    Ok(())
}

/// Log per-proposer packet/byte totals alongside the kernel counters.
fn report<T: Borrow<MapData>>(proposers: &[Proposer], stats_map: &PerCpuArray<T, u64>) {
    let active: Vec<String> = proposers
        .iter()
        .enumerate()
        .filter(|(_, p)| p.pkts > 0)
        .map(|(i, p)| format!("p{}={}pkt/{}B", i + 1, p.pkts, p.bytes))
        .collect();
    if active.is_empty() {
        info!("per-proposer: (none yet)");
    } else {
        info!("per-proposer: {}", active.join(" "));
    }
    stats::print(stats_map);
}
