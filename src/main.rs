use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Error, Result, anyhow};
use clap::{Parser, Subcommand};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::sethostname;

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Rust containerization software")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    Run {
        #[arg()]
        cmd: String,
        #[arg(long)]
        hostname: Option<OsString>,
        #[arg()]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Commands::Run {
        cmd,
        hostname,
        args,
    } = cli.command;

    run(cmd, hostname, args)
}

fn run(cmd: String, hostname: Option<OsString>, args: Vec<String>) -> Result<()> {
    println!("Running command: {} with args: {:?}", cmd, args);

    // SAFETY: TODO: Write this safety comment thouroughly explaining what you do in the `pre_exec`!
    let code = unsafe {
        Command::new(&cmd)
            .args(&args)
            .pre_exec(move || {
                println!("Child PID: {}", libc::getpid());

                map_root()?;

                unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS)?;

                if let Some(ref hostname) = hostname {
                    sethostname(hostname)?;
                }

                Ok(())
            })
            .spawn()
            .context("Failed to spawn command")?
            .wait()
            .context("Failed to wait on child process")?
            .code()
            .ok_or_else(|| anyhow!("Child process was terminated by signal"))
            .context("Failed to get exit code")?
    };

    println!("Child process exited with code {code}");

    Ok(())
}

fn map_root() -> io::Result<()> {
    // First, get user's UID and GID

    // SAFETY: `getuid` and `getgid` are documented (`man 2|3 getuid|getgid`) to never fail.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // New user namespace
    unshare(CloneFlags::CLONE_NEWUSER)?;

    // Map root user: method observed being (with strace) by `unshare --user --map-root-user`
    const UID_MAP_FILE: &str = "/proc/self/uid_map";
    const GID_MAP_FILE: &str = "/proc/self/gid_map";
    const SETGROUPS_FILE: &str = "/proc/self/setgroups";

    let mut fuid_map = File::create(UID_MAP_FILE)?;
    let mut fgid_map = File::create(GID_MAP_FILE)?;
    let mut fsetgroups = File::create(SETGROUPS_FILE)?;

    fuid_map.write_all(format!("0 {uid} 1").as_bytes())?;
    fsetgroups.write_all(b"deny")?;
    fgid_map.write_all(format!("0 {gid} 1").as_bytes())?;

    Ok(())
}
