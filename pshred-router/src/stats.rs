//! Reading the kernel `STATS` per-CPU counter array.
//!
//! Indices and names come from [`pshred_router_common::stats`], so the kernel
//! and userspace can never disagree on what each slot means.

use std::{
    borrow::Borrow,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use aya::maps::{MapData, PerCpuArray};
use log::info;
use pshred_router_common::stats;

use crate::RUNNING;

/// Sum one counter across every CPU.
pub fn read<T: Borrow<MapData>>(map: &PerCpuArray<T, u64>, idx: u32) -> u64 {
    map.get(&idx, 0)
        .map(|per_cpu| per_cpu.iter().copied().sum())
        .unwrap_or(0)
}

/// Log every counter as `name=value`.
pub fn print<T: Borrow<MapData>>(map: &PerCpuArray<T, u64>) {
    let vals: Vec<String> = (0..stats::COUNT)
        .map(|i| format!("{}={}", stats::NAMES[i as usize], read(map, i)))
        .collect();
    info!("stats: {}", vals.join(" "));
}

/// Attach-and-watch path: no AF_XDP, just surface the kernel counters once a
/// second until Ctrl-C or the optional duration elapses.
pub fn run_stats_only(ebpf: &aya::Ebpf, duration: Option<u64>) -> Result<()> {
    let map: PerCpuArray<_, u64> =
        PerCpuArray::try_from(ebpf.map("STATS").context("STATS map not found")?)?;
    info!("STATS-only mode; send pshreds to the interface and watch the counters");
    let start = Instant::now();
    while RUNNING.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(1));
        print(&map);
        if duration.is_some_and(|d| start.elapsed().as_secs() >= d) {
            break;
        }
    }
    print(&map);
    Ok(())
}
