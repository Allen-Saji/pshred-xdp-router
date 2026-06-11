//! Userspace loader for the pshred XDP demultiplexer.
//!
//! Loads and attaches the XDP program, then runs one of two paths:
//!
//! * `--no-xsk`: attach only and print the kernel `STATS` counters. This needs
//!   no privileges beyond loading XDP and is the quickest way to confirm the
//!   demux decision logic end to end.
//! * default: stand up one AF_XDP socket per proposer (see [`afxdp`]) and drain
//!   the per-proposer rings the kernel redirects into.

mod afxdp;
mod stats;

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context as _, Result};
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
use log::{info, warn};

/// Cleared by SIGINT so the drain and stats loops exit on Ctrl-C.
pub(crate) static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn on_sigint(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

#[derive(Debug, Parser)]
#[command(about = "XDP pshred demultiplexer: redirect per proposer into AF_XDP rings")]
struct Opt {
    /// Interface to attach the XDP program to.
    #[clap(short, long, default_value = "veth0")]
    iface: String,

    /// Attach and read STATS only; do not set up AF_XDP sockets.
    #[clap(long)]
    no_xsk: bool,

    /// Stop after this many seconds (default: run until Ctrl-C).
    #[clap(long)]
    duration: Option<u64>,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    raise_memlock();
    install_sigint();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pshred_router"
    )))
    .context("load eBPF object")?;

    let program: &mut Xdp = ebpf
        .program_mut("pshred_router")
        .context("program pshred_router not found")?
        .try_into()?;
    program.load().context("load XDP program")?;
    program
        .attach(&opt.iface, XdpMode::Skb)
        .with_context(|| format!("attach XDP to {} (SKB/generic mode)", opt.iface))?;
    info!("attached pshred_router to {} (SKB mode)", opt.iface);

    if opt.no_xsk {
        return stats::run_stats_only(&ebpf, opt.duration);
    }
    afxdp::run(&mut ebpf, &opt.iface, opt.duration)
}

/// eBPF maps are backed by locked memory; raise the limit so map creation does
/// not fail on systems with a low default.
fn raise_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
        warn!("could not raise RLIMIT_MEMLOCK; map creation may fail without root");
    }
}

fn install_sigint() {
    let handler = on_sigint as extern "C" fn(libc::c_int);
    unsafe { libc::signal(libc::SIGINT, handler as libc::sighandler_t) };
}
