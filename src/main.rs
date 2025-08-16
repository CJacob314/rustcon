mod temp_path_builder;

use clone_args_command::Command;
use nix::sched::{CloneFlags, unshare};
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::{env, fs};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use libc::rmdir;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
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

    /* Get user's effective UID and GID, which will be passed to map_root in the pre-exec.
     * This has to be done in the parent user-namespace (before `unshare` puts us in a new one).
     * SAFETY: `getuid` and `getgid` are documented (`man 2|3 getuid|getgid`) to never fail.
     */
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };

    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID)
        .with_context(|| "Failed to unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID)")?;

    // SAFETY: TODO: Write this safety comment, thoroughly explaining what you do in the `pre_exec`!
    let code = unsafe {
        Command::new(&cmd)
            .args(&args)
            .envs([
                ("USER", "root"),
                ("HOME", "/root"),
                ("PATH", "/bin:/usr/bin"),
                ("TERM", &term),
            ])
            .clone_flags(libc::CLONE_NEWUTS)
            .pre_exec(move || {
                println!("Child PID: {}", libc::getpid());

                // Map root user inside new user namespace
                map_root(uid, gid).with_context(|| "Failed to map root")?;

                if let Some(ref hostname) = hostname {
                    // Set hostname in the new UTS NS if we should
                    sethostname(hostname).with_context(|| "Failed to set hostname")?;
                }

                if let Some(ref rootfs) = rootfs {
                    // Make sure the new PID namespace was successfully created
                    assert_eq!(libc::getpid(), 1);

                    // Place ourselves in new IPC namespace
                    unshare(CloneFlags::CLONE_NEWIPC)?;

                    // Make new root mount private recursively
                    mount(
                        None::<&str>,
                        "/",
                        None::<&str>,
                        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
                        None::<&str>,
                    )
                    .context("Failed to make new root mount private")?;

                    // Bind mount rootfs over itself (as explained in `man 2 pivot_root`)
                    mount(
                        Some(rootfs),
                        rootfs,
                        None::<&str>,
                        MsFlags::MS_BIND,
                        None::<&str>,
                    )
                    .context("Failed to bind mount rootfs over itself")?;

                    // Create directory for old_root mount
                    let put_old = TempPathBuilder::new()
                        .parent(rootfs)
                        .prefix("put_old")
                        .length(12)
                        .build();
                    std::fs::create_dir(&put_old)
                        .with_context(|| "Failed to create directory for old_root mount")?;

                    // pivot_root call to change the root mount in the current (and new, from CLONE_NEWNS) mount namespace
                    pivot_root(rootfs, &put_old).context("Failed to pivot root")?;

                    // Ensure /proc directory exists
                    match fs::create_dir("/proc") {
                        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
                        _ => Ok(()),
                    }?;

                    /* Mount procfs to let programs like `ps` work.
                     * Flags chosen based on this weekly-news article: https://lwn.net/Articles/647757/
                     */
                    mount(
                        Some("proc"),
                        "/proc",
                        Some("proc"),
                        MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                        None::<&str>,
                    )
                    .with_context(|| "Failed to mount procfs in new mount namespace")?;

                    // Unmount the old root mount
                    let mount_name = put_old.file_name().unwrap();
                    let path_to_old_mount = PathBuf::from("/").join(mount_name);
                    umount2(&path_to_old_mount, MntFlags::MNT_DETACH)
                        .context("Failed to unmount old root")?;

                    // Finally, clean up by unlinking and deleting/freeing the put_old directory
                    let path_to_old_mount_c =
                        CString::new(path_to_old_mount.as_os_str().as_encoded_bytes())
                            .context("Failed to create CString for put_old mount")?;

                    if rmdir(path_to_old_mount_c.as_ptr()) < 0 {
                        return Err(io::Error::new(
                            io::Error::last_os_error().kind(),
                            "Failed to rmdir the path to old mount",
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

fn map_root(parent_euid: u32, parent_egid: u32) -> Result<()> {
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
        .write_all(format!("0 {parent_euid} 1").as_bytes())
        .context("Failed to write to uid_map File")?;
    fsetgroups
        .write_all(b"deny")
        .context("Failed to write to setgroups File")?;
    fgid_map
        .write_all(format!("0 {parent_egid} 1").as_bytes())
        .context("Failed to write to gid_map File")?;

    Ok(())
}
