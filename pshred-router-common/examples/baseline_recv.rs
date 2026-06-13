//! Baseline UDP receiver: one recv() syscall per packet, no kernel bypass.
//!
//! This is the comparison point for the AF_XDP fast path. It lives as an example
//! of `pshred-router-common` because that crate builds without the eBPF
//! toolchain (no bpf-linker / LLVM), so the baseline compiles on its own. Run it
//! WITHOUT the XDP program attached (the XDP redirect would otherwise steal the
//! packets before they reach this socket):
//!
//!   cargo build --release -p pshred-router-common --example baseline_recv
//!   sudo ip netns exec pshred ./target/release/examples/baseline_recv 10.0.0.2 9000
//!   # from the root ns, flood it:
//!   ./send_shred.sh 10.0.0.2 3 2000000
//!
//! It reports packets/second each interval. Compare pkt/s and CPU (e.g. `pidstat
//! -p <pid> 1`) against the AF_XDP loader under the same flood.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn main() {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0".to_string());
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    let sock = UdpSocket::bind((bind.as_str(), port)).expect("bind");
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    eprintln!("baseline UDP receiver on {bind}:{port} (1 syscall/packet)");

    let mut buf = [0u8; 2048];
    let mut count: u64 = 0;
    let mut bytes: u64 = 0;
    let mut total: u64 = 0;
    let mut window = Instant::now();

    loop {
        // A read timeout (WouldBlock) just falls through to the periodic report.
        if let Ok((n, _)) = sock.recv_from(&mut buf) {
            count += 1;
            bytes += n as u64;
            total += 1;
        }
        if window.elapsed() >= Duration::from_secs(1) {
            let secs = window.elapsed().as_secs_f64();
            println!(
                "{:.0} pkt/s  {:.1} MB/s  (total {})",
                count as f64 / secs,
                bytes as f64 / secs / 1e6,
                total
            );
            count = 0;
            bytes = 0;
            window = Instant::now();
        }
    }
}
