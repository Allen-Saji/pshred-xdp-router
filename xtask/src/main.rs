//! Developer task runner: toolchain setup, release build, and lint.
//!
//! Running the program needs root and a configured interface, so that step is
//! left to the documented `ip netns exec` invocation rather than wrapped here.

use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Build and lint the pshred XDP router")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install the nightly toolchain, rust-src, and bpf-linker.
    Setup,
    /// Build the loader and eBPF object in release mode.
    Build,
    /// Run clippy across all targets.
    Check,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Setup => setup()?,
        Cmd::Build => run_cargo("build", &["--release", "-p", "pshred-router"])?,
        Cmd::Check => run_cargo("clippy", &["--all-targets"])?,
    }
    Ok(())
}

fn setup() -> Result<()> {
    run(
        "rustup",
        &["toolchain", "install", "nightly", "--component", "rust-src"],
    )?;
    run("cargo", &["install", "bpf-linker"])?;
    Ok(())
}

fn run_cargo(cmd: &str, args: &[&str]) -> Result<()> {
    let mut all_args = vec![cmd];
    all_args.extend_from_slice(args);
    run("cargo", &all_args)
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    eprintln!("[xtask] $ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn `{program}`"))?;
    if !status.success() {
        match status.code() {
            Some(code) => bail!("`{program}` exited with status {code}"),
            None => bail!("`{program}` was terminated by a signal"),
        }
    }
    Ok(())
}
