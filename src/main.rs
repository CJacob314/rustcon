mod temp_path_builder;

use clone_args_command::Command;
use std::env;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use libc::rmdir;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{chdir, pivot_root, sethostname};
use temp_path_builder::TempPathBuilder;

#[derive(Parser, Debug)]
#[command(version, about, long_about = "Rust containerization software")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand, Clone)]
enum Commands {
    Run {
        #[arg(long)]
        /// Initial hostname to set inside the container
        hostname: Option<OsString>,
        #[arg(long, short)]
        /// Path to container root filesystem (will use a new mount namespace with old mounts if not specified)
        rootfs: Option<PathBuf>,
        #[arg()]
        /// Command to run inside the container
        cmd: String,
        #[arg()]
        /// Arguments to pass to the command
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Commands::Run {
        hostname,
        args,
        rootfs,
        cmd,
    } = cli.command;

    run(cmd, rootfs, hostname, args)
}

fn run(
    cmd: String,
    rootfs: Option<PathBuf>,
    hostname: Option<OsString>,
    args: Vec<String>,
) -> Result<()> {
    println!("Running command: {} with args: {:?}", cmd, args);

    let term = env::var("TERM").unwrap_or("xterm".into());

    // SAFETY: TODO: Write this safety comment thouroughly explaining what you do in the `pre_exec`!
    let code = unsafe {
        Command::new(&cmd)
            .args(&args)
            .envs([
                ("USER", "root"),
                ("HOME", "/root"),
                ("PATH", "/bin:/usr/bin"),
                ("TERM", &term),
            ])
            .pre_exec(move || {
                println!("Child PID: {}", libc::getpid());

                map_root().context("Failed to map root")?;

                // TODO: Figure out creating a new PID namespace
                unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS)
                    .context("unshare call for NEWNS and NEWUTS failed")?;

                if let Some(ref hostname) = hostname {
                    sethostname(hostname).context("Failed to set hostname")?;
                }

                if let Some(ref rootfs) = rootfs {
                    let put_old = TempPathBuilder::new()
                        .parent(rootfs)
                        .prefix("put_old")
                        .length(12)
                        .build();
                    std::fs::create_dir(&put_old)
                        .context("Failed to create directory for old_root mount")?; // Create directory for old_root mount

                    // Bind mount rootfs over itself (as explained in `man 2 pivot_root`)
                    mount(
                        Some(rootfs),
                        rootfs,
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .context("Failed to bind mount rootfs over itself")?;

                    // pivot_root call to change the root mount in the current (and new, from CLONE_NEWNS) mount namespace
                    pivot_root(rootfs, &put_old).context("Failed to pivot root")?;

                    // Unmount the old root mount
                    let mount_name = put_old.file_name().unwrap();
                    let path_to_old_mount = PathBuf::from("/").join(mount_name);
                    umount2(&path_to_old_mount, MntFlags::MNT_DETACH)
                        .context("Failed to unmount old root")?;

                    // Finally, clean up by unlinking the put_old directory
                    let path_to_old_mount_c =
                        CString::new(path_to_old_mount.as_os_str().as_encoded_bytes())
                            .context("Failed to create CString for put_old mount")?;

                    if rmdir(path_to_old_mount_c.as_ptr()) < 0 {
                        return Err(io::Error::new(
                            io::Error::last_os_error().kind(),
                            format!("Failed to rmdir the path to old mount"),
                        )
                        .into());
                    }

                    // Switch directory to the new root dir
                    chdir("/").context("Failed to change directory to new root dir")?;
                }

                Ok(())
            })
            .spawn()
            .context("Failed to spawn command")?
            .wait()
            .context("Failed to wait on child process")?
            .code()
            .ok_or_else(|| anyhow!("Child process was terminated or stopped by a signal"))
            .context("Failed to get exit code")?
    };

    println!("Child process exited with code {code}");

    Ok(())
}

fn map_root() -> Result<()> {
    // First, get user's UID and GID

    // SAFETY: `getuid` and `getgid` are documented (`man 2|3 getuid|getgid`) to never fail.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // New user namespace
    unshare(CloneFlags::CLONE_NEWUSER)
        .context("Failed to create new user namespace with unshare in map_root")?;

    // Map root user: method observed being (with strace) by `unshare --user --map-root-user`
    const UID_MAP_FILE: &str = "/proc/self/uid_map";
    const GID_MAP_FILE: &str = "/proc/self/gid_map";
    const SETGROUPS_FILE: &str = "/proc/self/setgroups";

    let mut fuid_map =
        File::create(UID_MAP_FILE).context("Failed to create Rust File for procfs uid_map")?;
    let mut fgid_map =
        File::create(GID_MAP_FILE).context("Failed to create Rust File for procfs gid_map")?;
    let mut fsetgroups =
        File::create(SETGROUPS_FILE).context("Failed to create Rust File for procfs setgroups")?;

    fuid_map
        .write_all(format!("0 {uid} 1").as_bytes())
        .context("Failed to write to uid_map File")?;
    fsetgroups
        .write_all(b"deny")
        .context("Failed to write to setgroups File")?;
    fgid_map
        .write_all(format!("0 {gid} 1").as_bytes())
        .context("Failed to write to gid_map File")?;

    Ok(())
}
