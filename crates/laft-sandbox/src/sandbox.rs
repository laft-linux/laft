use std::ffi::{CStr, CString, OsStr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Child, ExitStatus, Output, Stdio};

use rustix::fs::{CWD, Mode, OFlags};
use rustix::io::Errno;
use rustix::mount::{
    FsMountFlags, FsOpenFlags, MountAttrFlags, MountPropagationFlags, MoveMountFlags,
    OpenTreeFlags, UnmountFlags,
};
use rustix::pipe::PipeFlags;
use rustix::process::{Gid, Pid, Resource, Rlimit, Signal, Uid, WaitOptions, umask};
use rustix::thread::{CapabilitySet, UnshareFlags};

use crate::error::{Error, Step};
use crate::fixed::{FixedRoot, FixedSandbox, NOBODY};
use crate::root::{RootSandbox, RootTree};
use crate::sys::{self, Fork};

/// The hostname and domain name inside every sandbox.
pub const HOSTNAME: &str = "laft-build";

/// The highest number of open files a sandboxed process may have, unless the
/// caller's own hard limit is lower.
pub const MAX_OPEN_FILES: u64 = 65536;

/// The device nodes bound into the sandbox's `/dev`.
const DEVICES: [(&CStr, &CStr); 6] = [
    (c"/dev/null", c"null"),
    (c"/dev/zero", c"zero"),
    (c"/dev/full", c"full"),
    (c"/dev/random", c"random"),
    (c"/dev/urandom", c"urandom"),
    (c"/dev/tty", c"tty"),
];

const DEVICE_LINKS: [(&CStr, &CStr); 4] = [
    (c"fd", c"/proc/self/fd"),
    (c"stdin", c"/proc/self/fd/0"),
    (c"stdout", c"/proc/self/fd/1"),
    (c"stderr", c"/proc/self/fd/2"),
];

/// The host files bound into `/etc` with [`Network::Host`], when the host
/// has them.
const HOST_ETC: [(&CStr, &CStr); 3] = [
    (c"/etc/resolv.conf", c"resolv.conf"),
    (c"/etc/hosts", c"hosts"),
    (c"/etc/nsswitch.conf", c"nsswitch.conf"),
];

const ROOT_DIRS: [&CStr; 7] = [c"usr", c"build", c"out", c"proc", c"dev", c"tmp", c"etc"];

/// The uid and gid of the check user, which a command that
/// [`Command::check_user`] names runs as inside the sandbox. Its host id
/// is the caller's first subordinate id, or the same number when the
/// caller is root.
const CHECK_ID: u32 = 100;

/// The user database of `/etc`, which names the only ids a command runs
/// as and sees, so that programs that look up their user or group find
/// one.
const USER_FILES: [(&CStr, &[u8]); 2] = [
    (
        c"passwd",
        b"root:x:0:0:root:/build/home:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n",
    ),
    (c"group", b"root:x:0:\nnogroup:x:65534:\n"),
];

/// The user database of `/etc` with the check user, whose ids the user
/// namespace maps when a command runs as it.
const USER_FILES_CHECK: [(&CStr, &[u8]); 2] = [
    (
        c"passwd",
        b"root:x:0:0:root:/build/home:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\ncheck:x:100:100:check:/build/home:/bin/false\n",
    ),
    (c"group", b"root:x:0:\nnogroup:x:65534:\ncheck:x:100:\n"),
];

/// The name service files of `/etc` in an isolated sandbox, whose
/// loopback interface is up, so that `localhost` names it. Without a
/// `nsswitch.conf`, the C library would ask a name server first and give
/// up when none answers.
const LOOPBACK_FILES: [(&CStr, &[u8]); 2] = [
    (c"hosts", b"127.0.0.1 localhost\n::1 localhost\n"),
    (
        c"nsswitch.conf",
        b"passwd: files\ngroup: files\nhosts: files\n",
    ),
];

pub(crate) const ROOT_LINKS: [(&CStr, &CStr); 4] = [
    (c"bin", c"usr/bin"),
    (c"sbin", c"usr/bin"),
    (c"lib", c"usr/lib"),
    (c"lib64", c"usr/lib"),
];

/// How a sandbox reaches the network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Network {
    /// A new network namespace whose only interface is a loopback interface,
    /// which is up, so that a command reaches its own sockets and nothing
    /// else. `/etc` holds the user database and the `hosts` and
    /// `nsswitch.conf` files that name the interface `localhost`.
    #[default]
    Isolated,
    /// The caller's network namespace, for the phase that fetches sources.
    ///
    /// So that names resolve, the host's `/etc/resolv.conf`, `/etc/hosts`
    /// and `/etc/nsswitch.conf` are bound read-only into the read-only
    /// `/etc`, next to the user database. A file the host lacks is left
    /// out.
    Host,
}

/// The layout of a build sandbox: a view as `/usr`, a writable `/build` and
/// a writable `/out`.
///
/// Every command started from a sandbox runs as uid 0 and gid 0 inside new
/// user, mount, PID, IPC and UTS namespaces, and a new network namespace
/// unless [`Network::Host`] is chosen. Those ids map to the caller's own uid
/// and gid, so files the command writes to `/build` and `/out` belong to the
/// caller. The command sees this tree and nothing else of the host:
///
/// | Path | Contents |
/// |---|---|
/// | `/` | an empty tmpfs, read-only |
/// | `/usr` | the view, read-only, `nosuid`, `nodev` |
/// | `/bin`, `/sbin` | symlinks to `usr/bin` |
/// | `/lib`, `/lib64` | symlinks to `usr/lib` |
/// | `/build` | the build directory, writable, the working directory |
/// | `/out` | the output directory, writable |
/// | `/proc` | a new procfs that shows only the sandbox's processes |
/// | `/dev` | a read-only tmpfs with `null`, `zero`, `full`, `random`, `urandom` and `tty` bound from the host, `fd`, `stdin`, `stdout`, `stderr` links, a private pseudo-terminal filesystem at `pts` with `ptmx` linking to its multiplexer, and a private tmpfs at `shm` |
/// | `/tmp` | a private tmpfs |
/// | `/etc` | read-only, with `passwd` and `group` naming `root` and `nobody`, and with the sandbox's check user when a command runs as it, and `hosts` and `nsswitch.conf` naming the loopback interface `localhost` or, with [`Network::Host`], the host's name resolution files |
///
/// Before the command is executed, its capability bounding set is emptied,
/// `no_new_privs` is set, the core size limit is 0 and the open file limit
/// is [`MAX_OPEN_FILES`]. Its environment holds only `PATH=/usr/bin` and
/// what [`Command::env`] adds. The hostname is [`HOSTNAME`].
///
/// # Examples
///
/// ```no_run
/// use std::process::Stdio;
///
/// use laft_sandbox::Sandbox;
///
/// let sandbox = Sandbox::new("work/k/root/usr", "work/k/build", "work/k/out");
/// let output = sandbox
///     .command("/usr/bin/bash")
///     .arg("-c")
///     .arg("make && make DESTDIR=/out install")
///     .stdin(Stdio::null())
///     .output()?;
/// assert!(output.status.success());
/// # Ok::<(), laft_sandbox::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Sandbox {
    view: PathBuf,
    build: PathBuf,
    out: PathBuf,
    network: Network,
    /// The pipe of a jobserver, bound into every command at
    /// `/build/jobserver`.
    jobserver: Option<PathBuf>,
}

impl Sandbox {
    /// A sandbox with `view` as `/usr`, `build` as `/build` and `out` as
    /// `/out`, and no network.
    ///
    /// `view` is the `usr` tree of an assembled view. The directories are
    /// looked up when a command is spawned.
    pub fn new(
        view: impl Into<PathBuf>,
        build: impl Into<PathBuf>,
        out: impl Into<PathBuf>,
    ) -> Self {
        Self {
            view: view.into(),
            build: build.into(),
            out: out.into(),
            network: Network::Isolated,
            jobserver: None,
        }
    }

    /// Chooses how commands reach the network.
    pub fn network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Binds the named pipe at `path` into every command as
    /// `/build/jobserver`, where a build that joins a jobserver finds it.
    pub fn jobserver(mut self, path: impl Into<PathBuf>) -> Self {
        self.jobserver = Some(path.into());
        self
    }

    /// A command that runs `program` inside this sandbox.
    ///
    /// A `program` without a slash is searched in `PATH` inside the sandbox.
    pub fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut inner = process::Command::new(program);
        inner.env_clear().env("PATH", "/usr/bin");
        Command::new(Layout::Build(self.clone()), inner)
    }
}

/// The kind of sandbox a command runs in.
#[derive(Debug, Clone)]
pub(crate) enum Layout {
    /// A build sandbox.
    Build(Sandbox),
    /// A sandbox for a fixed program.
    Fixed(FixedSandbox),
    /// A sandbox rooted in an existing tree.
    Root(RootSandbox),
}

/// A command to run in a [`Sandbox`], configured like
/// [`std::process::Command`].
///
/// The sandbox fixes the working directory, the ids and the root, so only
/// the arguments, the environment and the standard streams can be set.
#[derive(Debug)]
pub struct Command {
    layout: Layout,
    inner: process::Command,
    stdin_set: bool,
    check_user: bool,
}

impl Command {
    pub(crate) fn new(layout: Layout, inner: process::Command) -> Self {
        Self {
            layout,
            inner,
            stdin_set: false,
            check_user: false,
        }
    }

    /// Runs the command as the check user inside its build sandbox: uid
    /// and gid 100, named `check` in the sandbox's `/etc`, with
    /// home `/build/home`, instead of root. The user namespace maps that
    /// id to a second host id: the caller's first subordinate id through
    /// `newuidmap` and `newgidmap` when the caller is not root, or a map
    /// the sandbox child writes itself when it is. The check user leaves
    /// every file it creates open to everyone, so that the caller can
    /// clean up after the build. It has an effect only in a build sandbox;
    /// the other layouts run the command as they would without it.
    pub fn check_user(mut self) -> Self {
        self.check_user = true;
        self
    }

    /// Adds an argument.
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.inner.arg(arg);
        self
    }

    /// Adds several arguments.
    pub fn args(mut self, args: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Self {
        self.inner.args(args);
        self
    }

    /// Sets an environment variable, replacing an earlier value, including
    /// the default `PATH`.
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.inner.env(key, value);
        self
    }

    /// Sets the command's standard input. It is inherited by default, except
    /// by [`Command::output`].
    pub fn stdin(mut self, stdin: impl Into<Stdio>) -> Self {
        self.inner.stdin(stdin);
        self.stdin_set = true;
        self
    }

    /// Sets the command's standard output. It is inherited by default.
    pub fn stdout(mut self, stdout: impl Into<Stdio>) -> Self {
        self.inner.stdout(stdout);
        self
    }

    /// Sets the command's standard error. It is inherited by default.
    pub fn stderr(mut self, stderr: impl Into<Stdio>) -> Self {
        self.inner.stderr(stderr);
        self
    }

    /// Sets up the sandbox and starts the command in it.
    ///
    /// The returned [`Child`] is a small process outside the sandbox that
    /// waits for the command and exits the way it did, with the same code
    /// or killed by the same signal. The command itself runs as PID 1 of the
    /// sandbox, so it should reap the processes it starts, as shells do.
    /// Killing the child with [`Child::kill`] kills every process of the
    /// sandbox. Dropping it does not.
    ///
    /// Use piped standard streams to read the command's output while it
    /// runs.
    ///
    /// Every signal has its default disposition in the sandbox, even one
    /// the caller ignores, so the command can wait for its own children and
    /// is interrupted like any program.
    ///
    /// A command whose standard input was set leads a session of its own,
    /// without a controlling terminal, so that what it sees does not depend
    /// on the terminal of its caller. A command that inherits standard
    /// input, such as an interactive shell, stays in the caller's session
    /// and keeps its terminal.
    ///
    /// # Errors
    ///
    /// Fails when a directory of the sandbox does not exist, when a step of
    /// the setup fails, for example because the kernel forbids unprivileged
    /// user namespaces, or when the program cannot be executed. The error
    /// names the step.
    pub fn spawn(self) -> Result<Child, Error> {
        let Self {
            layout,
            mut inner,
            stdin_set,
            check_user,
        } = self;
        let setup = Setup {
            new_session: stdin_set,
            ..Setup::new(&layout, check_user)?
        };
        let (reader, writer) =
            rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(|e| Error::new(Step::Pipe, e))?;
        let hook = move || setup.run(writer.as_fd());
        // SAFETY: the hook runs in the forked child before `exec`. It only
        // makes system calls on data prepared before the fork and never
        // allocates, takes a lock or touches state shared with other threads
        // of the parent, which is what a child of a multithreaded process
        // may do.
        unsafe { inner.pre_exec(hook) };
        let spawned = inner.spawn();
        drop(inner);
        spawned.map_err(|error| {
            let mut code = [0u8];
            // The setup hook reports its step before failing. Without a
            // report, the hook succeeded and `exec` failed.
            let step = match rustix::io::read(&reader, &mut code) {
                Ok(1) => Step::from_code(code[0]),
                _ => Step::Exec,
            };
            Error::new(step, error)
        })
    }

    /// Runs the command to completion with captured standard output and
    /// standard error, and returns them with its exit status.
    ///
    /// Standard input is null unless [`Command::stdin`] set it, so a command
    /// that reads it sees end of file at once.
    ///
    /// # Errors
    ///
    /// Fails like [`Command::spawn`], or when reading the output fails.
    pub fn output(mut self) -> Result<Output, Error> {
        if !self.stdin_set {
            self = self.stdin(Stdio::null());
        }
        let child = self.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        child
            .wait_with_output()
            .map_err(|e| Error::new(Step::Wait, e))
    }

    /// Runs the command to completion and returns its exit status.
    ///
    /// # Errors
    ///
    /// Fails like [`Command::spawn`], or when waiting for it fails.
    pub fn status(self) -> Result<ExitStatus, Error> {
        self.spawn()?.wait().map_err(|e| Error::new(Step::Wait, e))
    }
}

/// Everything the forked child needs, prepared before the fork so that the
/// child never allocates.
struct Setup {
    namespaces: UnshareFlags,
    /// How the child maps the ids of its new user namespace, or `None`
    /// when it creates none.
    id_maps: Option<IdMap>,
    open_files: u64,
    root: RootSetup,
    /// Whether the command leads a session of its own, without a
    /// controlling terminal.
    new_session: bool,
    /// The process that spawns the sandbox.
    caller: Pid,
}

/// How the ids of a new user namespace are mapped.
enum IdMap {
    /// The child writes the maps itself, one write per file: one line
    /// mapping its own ids, or two lines with the check user for a root
    /// caller.
    Own(Vec<u8>, Vec<u8>),
    /// The child has the ids mapped through `newuidmap` and `newgidmap`,
    /// which only the caller's subordinate ranges let write a second id.
    Helpers(Box<HelperCall>, Box<HelperCall>),
}

/// A prepared call of an id mapping helper: the path of the setuid
/// program and the arguments that follow the target pid, which the child
/// names when it runs.
struct HelperCall {
    path: CString,
    args: [CString; 6],
}

/// How the child builds its root.
enum RootSetup {
    Build(BuildRoot),
    Fixed(FixedRoot),
    Root(RootTree),
}

/// The root of a build sandbox.
struct BuildRoot {
    view: CString,
    build: CString,
    out: CString,
    host_etc: bool,
    /// The pipe of a jobserver, bound at `/build/jobserver`.
    jobserver: Option<CString>,
    /// Whether the command runs as the check user, which names its ids in
    /// `/etc` and whose init the child drops to before the command.
    check_user: bool,
}

pub(crate) type Failure = (Step, Errno);

pub(crate) fn fail(step: Step) -> impl Fn(Errno) -> Failure {
    move |errno| (step, errno)
}

/// `path` with every symlink resolved, as a C string for the child.
pub(crate) fn resolve(path: &Path) -> Result<CString, Error> {
    let path = std::fs::canonicalize(path).map_err(|e| Error::at(Step::Resolve, path, e))?;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|e| Error::at(Step::Resolve, &path, std::io::Error::other(e)))
}

impl Setup {
    fn new(layout: &Layout, check_user: bool) -> Result<Self, Error> {
        let mut namespaces = UnshareFlags::NEWNS
            | UnshareFlags::NEWPID
            | UnshareFlags::NEWIPC
            | UnshareFlags::NEWUTS;
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let (root, inside, user_namespace) = match layout {
            Layout::Build(sandbox) => {
                if sandbox.network == Network::Isolated {
                    namespaces |= UnshareFlags::NEWNET;
                }
                let root = RootSetup::Build(BuildRoot {
                    view: resolve(&sandbox.view)?,
                    build: resolve(&sandbox.build)?,
                    out: resolve(&sandbox.out)?,
                    host_etc: sandbox.network == Network::Host,
                    jobserver: sandbox.jobserver.as_deref().map(resolve).transpose()?,
                    check_user,
                });
                (root, 0, true)
            }
            Layout::Fixed(sandbox) => {
                namespaces |= UnshareFlags::NEWNET;
                let privileged = rustix::process::geteuid().is_root();
                let root = RootSetup::Fixed(FixedRoot::new(sandbox, privileged)?);
                (root, NOBODY, !privileged)
            }
            Layout::Root(sandbox) => {
                namespaces |= UnshareFlags::NEWNET;
                (RootSetup::Root(RootTree::new(sandbox)?), 0, true)
            }
        };
        let id_maps = user_namespace
            .then(|| {
                namespaces |= UnshareFlags::NEWUSER;
                match (layout, check_user, uid == 0) {
                    // Only the build sandbox has a check user, so only it
                    // maps a second id for one.
                    (Layout::Build(_), true, true) => Ok(IdMap::Own(
                        format!("0 {uid} 1\n{CHECK_ID} {CHECK_ID} 1\n").into_bytes(),
                        format!("0 {gid} 1\n{CHECK_ID} {CHECK_ID} 1\n").into_bytes(),
                    )),
                    (Layout::Build(_), true, false) => {
                        helper_calls(uid, gid).map(|(uid_call, gid_call)| {
                            IdMap::Helpers(Box::new(uid_call), Box::new(gid_call))
                        })
                    }
                    _ => Ok(IdMap::Own(
                        format!("{inside} {uid} 1\n").into_bytes(),
                        format!("{inside} {gid} 1\n").into_bytes(),
                    )),
                }
            })
            .transpose()?;
        let hard = rustix::process::getrlimit(Resource::Nofile).maximum;
        Ok(Self {
            namespaces,
            id_maps,
            open_files: hard.map_or(MAX_OPEN_FILES, |hard| hard.min(MAX_OPEN_FILES)),
            root,
            new_session: false,
            caller: rustix::process::getpid(),
        })
    }

    /// Runs in the child of `fork`. On failure it sends the failed step to
    /// the parent through `report` before the standard library reports the
    /// error number.
    fn run(&self, report: BorrowedFd<'_>) -> std::io::Result<()> {
        self.enter().map_err(|(step, errno)| {
            let _ = rustix::io::write(report, &[step as u8]);
            errno.into()
        })
    }

    fn enter(&self) -> Result<(), Failure> {
        // The sandbox dies with its caller, so that nothing it runs keeps
        // writing after the caller is gone. The signal follows the thread
        // that spawned the sandbox, which waits for it. A caller that died
        // before the signal was set is caught by its parent id.
        rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
            .map_err(fail(Step::DeathSignal))?;
        if rustix::process::getppid() != Some(self.caller) {
            return Err((Step::DeathSignal, Errno::SRCH));
        }
        // The kernel ignores the setuid bit of a program that a namespace
        // without maps execs, so the id mapping helpers, which carry it,
        // are forked before this process enters the namespace, while its
        // ids are still the caller's.
        let helpers = match &self.id_maps {
            Some(IdMap::Helpers(uid_call, gid_call)) => {
                Some((fork_helper(uid_call)?, fork_helper(gid_call)?))
            }
            _ => None,
        };
        match helpers {
            Some((uid_helper, gid_helper)) => {
                sys::unshare(self.namespaces).map_err(fail(Step::Unshare))?;
                write_proc(c"/proc/self/setgroups", b"deny")?;
                run_helper(uid_helper)?;
                run_helper(gid_helper)?;
            }
            None => {
                sys::unshare(self.namespaces).map_err(fail(Step::Unshare))?;
                if let Some(IdMap::Own(uid_map, gid_map)) = &self.id_maps {
                    write_proc(c"/proc/self/setgroups", b"deny")?;
                    write_proc(c"/proc/self/uid_map", uid_map)?;
                    write_proc(c"/proc/self/gid_map", gid_map)?;
                }
            }
        }
        let open_files = Rlimit {
            current: Some(self.open_files),
            maximum: Some(self.open_files),
        };
        let no_core = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        rustix::process::setrlimit(Resource::Nofile, open_files).map_err(fail(Step::Limits))?;
        rustix::process::setrlimit(Resource::Core, no_core).map_err(fail(Step::Limits))?;

        // An ignored disposition survives the fork and `exec`, so a command
        // would inherit every signal its caller ignores, for example SIGINT
        // and SIGQUIT of a job started in the background. An ignored SIGCHLD
        // would even make the kernel reap children on its own, so that
        // `wait_for` could not learn how PID 1 ended.
        crate::process::reset_signal_dispositions();
        // The new PID namespace applies to children only. This process stays
        // outside as the one the caller waits for, and the forked child
        // becomes PID 1 of the sandbox.
        // SAFETY: both sides of the fork only make system calls and never
        // allocate or take locks.
        match unsafe { sys::fork() }.map_err(fail(Step::Fork))? {
            Fork::Parent(init) => wait_for(init),
            Fork::Child => {
                prepare_init()?;
                if self.new_session {
                    rustix::process::setsid().map_err(fail(Step::Session))?;
                }
                match &self.root {
                    RootSetup::Build(root) => root.build(),
                    RootSetup::Fixed(root) => root.build(),
                    RootSetup::Root(root) => root.build(),
                }
            }
        }
    }
}

/// Ties PID 1 of the sandbox to the waiting process and makes every mount
/// private.
fn prepare_init() -> Result<(), Failure> {
    // When the waiting process dies, for example from `Child::kill`, the
    // kernel kills PID 1 and with it the whole namespace.
    rustix::process::set_parent_process_death_signal(Some(Signal::KILL))
        .map_err(fail(Step::DeathSignal))?;
    rustix::mount::mount_change(
        c"/",
        MountPropagationFlags::PRIVATE | MountPropagationFlags::REC,
    )
    .map_err(fail(Step::Propagation))
}

impl BuildRoot {
    fn build(&self) -> Result<(), Failure> {
        let nosuid = MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NODEV;
        let view = clone_tree(&self.view, nosuid | MountAttrFlags::MOUNT_ATTR_RDONLY)?;
        let build = clone_tree(&self.build, nosuid)?;
        let out = clone_tree(&self.out, nosuid)?;

        // The new root is stacked on top of the old one. Paths keep resolving
        // in the old root until `pivot_root`, so host device nodes can still
        // be cloned below.
        let root = new_root()?;
        for dir in ROOT_DIRS {
            rustix::fs::mkdirat(&root, dir, Mode::from_raw_mode(0o755))
                .map_err(fail(Step::Populate))?;
        }
        for (link, target) in ROOT_LINKS {
            rustix::fs::symlinkat(target, &root, link).map_err(fail(Step::Populate))?;
        }
        attach(&view, &root, c"usr")?;
        attach(&build, &root, c"build")?;
        attach(&out, &root, c"out")?;
        if let Some(jobserver) = &self.jobserver {
            // The mount point of the pipe has to exist inside the tree, so
            // the child makes an empty file there first and binds the pipe
            // over it.
            drop(
                rustix::fs::openat(
                    &build,
                    c"jobserver",
                    OFlags::WRONLY | OFlags::CREATE | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map_err(fail(Step::Jobserver))?,
            );
            let fifo = clone_tree(jobserver, nosuid)?;
            attach(&fifo, &build, c"jobserver")?;
        }
        let proc = fresh_mount(c"proc", None, nosuid | MountAttrFlags::MOUNT_ATTR_NOEXEC)
            .map_err(fail(Step::MountProc))?;
        attach(&proc, &root, c"proc")?;
        mount_dev(&root, true)?;
        let tmp = fresh_mount(c"tmpfs", Some(c"1777"), nosuid).map_err(fail(Step::MountTmp))?;
        attach(&tmp, &root, c"tmp")?;
        write_etc(
            &root,
            if self.check_user {
                &USER_FILES_CHECK
            } else {
                &USER_FILES
            },
        )?;
        if self.host_etc {
            mount_host_etc(&root)?;
        } else {
            write_etc(&root, &LOOPBACK_FILES)?;
            sys::loopback_up().map_err(fail(Step::Loopback))?;
        }
        enter_root(&root)?;
        rustix::process::chdir(c"/build").map_err(fail(Step::WorkingDirectory))?;
        // The identity drop needs CAP_SETUID and CAP_SETGID in the
        // effective set, and clearing the bounding set needs CAP_SETPCAP,
        // so the bounding set goes first: changing to the check user
        // clears the effective set, but nothing it needs after that.
        drop_capabilities()?;
        if self.check_user {
            drop_to_check_user()?;
        }
        rustix::thread::set_no_new_privs(true).map_err(fail(Step::NoNewPrivs))?;
        sys::cloexec_from(3).map_err(fail(Step::Descriptors))
    }
}

/// Drops the init of the sandbox to the check user, so that the command
/// it execs runs as uid and gid [`CHECK_ID`], and leaves every file it
/// creates open to everyone, which lets the caller clean up after the
/// build. The supplementary groups the command inherited stay: the
/// namespace that mapped its ids refuses setgroups, and they grant
/// nothing the id itself does not.
fn drop_to_check_user() -> Result<(), Failure> {
    let gid = Gid::from_raw(CHECK_ID);
    let uid = Uid::from_raw(CHECK_ID);
    rustix::thread::set_thread_res_gid(gid, gid, gid).map_err(fail(Step::CheckUser))?;
    rustix::thread::set_thread_res_uid(uid, uid, uid).map_err(fail(Step::CheckUser))?;
    umask(Mode::empty());
    Ok(())
}

/// Creates an empty tmpfs and stacks it on `/`, where it becomes the root
/// once [`enter_root`] runs. Paths keep resolving in the old root until
/// then.
pub(crate) fn new_root() -> Result<OwnedFd, Failure> {
    let nosuid = MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NODEV;
    let root = fresh_mount(c"tmpfs", Some(c"0755"), nosuid).map_err(fail(Step::RootFs))?;
    rustix::mount::move_mount(
        &root,
        c"",
        CWD,
        c"/",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(fail(Step::RootFs))?;
    Ok(root)
}

/// Makes `root` read-only, switches to it, detaches the old root and sets
/// the hostname.
pub(crate) fn enter_root(root: &OwnedFd) -> Result<(), Failure> {
    sys::mount_setattr(
        root.as_fd(),
        MountAttrFlags::MOUNT_ATTR_RDONLY,
        MountAttrFlags::empty(),
    )
    .map_err(fail(Step::SetAttributes))?;
    switch_root(root)
}

/// Switches to `root`, which is stacked on `/`, detaches the old root and
/// sets the hostname.
pub(crate) fn switch_root(root: &OwnedFd) -> Result<(), Failure> {
    // With both arguments ".", the old root ends up stacked on the new
    // one, and detaching "." removes it.
    rustix::process::fchdir(root).map_err(fail(Step::PivotRoot))?;
    rustix::process::pivot_root(c".", c".").map_err(fail(Step::PivotRoot))?;
    rustix::mount::unmount(c".", UnmountFlags::DETACH).map_err(fail(Step::PivotRoot))?;
    rustix::process::chdir(c"/").map_err(fail(Step::PivotRoot))?;

    rustix::system::sethostname(HOSTNAME.as_bytes()).map_err(fail(Step::Hostname))?;
    rustix::system::setdomainname(HOSTNAME.as_bytes()).map_err(fail(Step::Hostname))
}

/// Mounts the sandbox's `/dev` in `root`. When `private` is set, it also
/// gets a private instance of the pseudo-terminal filesystem at `/dev/pts`,
/// with `/dev/ptmx` linking to its multiplexer, and a private tmpfs at
/// `/dev/shm`. Test suites drive programs through terminals and open POSIX
/// shared memory and semaphores there, and private instances show nothing
/// of the host.
pub(crate) fn mount_dev(root: &OwnedFd, private: bool) -> Result<(), Failure> {
    let dev = fresh_mount(
        c"tmpfs",
        Some(c"0755"),
        MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NOEXEC,
    )
    .map_err(fail(Step::MountDev))?;
    attach(&dev, root, c"dev")?;
    for (source, name) in DEVICES {
        let node = rustix::mount::open_tree(
            CWD,
            source,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )
        .map_err(fail(Step::MountDev))?;
        rustix::fs::openat(
            &dev,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o666),
        )
        .map_err(fail(Step::MountDev))?;
        attach(&node, &dev, name)?;
    }
    for (link, target) in DEVICE_LINKS {
        rustix::fs::symlinkat(target, &dev, link).map_err(fail(Step::MountDev))?;
    }
    if private {
        rustix::fs::mkdirat(&dev, c"shm", Mode::from_raw_mode(0o755))
            .map_err(fail(Step::MountDev))?;
        let shm = fresh_mount(
            c"tmpfs",
            Some(c"1777"),
            MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC,
        )
        .map_err(fail(Step::MountDev))?;
        attach(&shm, &dev, c"shm")?;
        rustix::fs::mkdirat(&dev, c"pts", Mode::from_raw_mode(0o755))
            .map_err(fail(Step::MountDev))?;
        let pts = (|| {
            let context = rustix::mount::fsopen(c"devpts", FsOpenFlags::FSOPEN_CLOEXEC)?;
            rustix::mount::fsconfig_set_string(&context, c"ptmxmode", c"0666")?;
            rustix::mount::fsconfig_set_string(&context, c"mode", c"0620")?;
            rustix::mount::fsconfig_create(&context)?;
            rustix::mount::fsmount(
                &context,
                FsMountFlags::FSMOUNT_CLOEXEC,
                MountAttrFlags::MOUNT_ATTR_NOSUID | MountAttrFlags::MOUNT_ATTR_NOEXEC,
            )
        })()
        .map_err(fail(Step::MountDev))?;
        attach(&pts, &dev, c"pts")?;
        rustix::fs::symlinkat(c"pts/ptmx", &dev, c"ptmx").map_err(fail(Step::MountDev))?;
    }
    sys::mount_setattr(
        dev.as_fd(),
        MountAttrFlags::MOUNT_ATTR_RDONLY,
        MountAttrFlags::empty(),
    )
    .map_err(fail(Step::MountDev))
}

/// Writes `files` into `/etc` of `root`, which becomes read-only with the
/// root.
fn write_etc(root: &OwnedFd, files: &[(&CStr, &[u8])]) -> Result<(), Failure> {
    let etc = rustix::fs::openat(
        root,
        c"etc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fail(Step::Populate))?;
    for &(name, contents) in files {
        let file = rustix::fs::openat(
            &etc,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(fail(Step::Populate))?;
        let written = rustix::io::write(&file, contents).map_err(fail(Step::Populate))?;
        if written != contents.len() {
            return Err((Step::Populate, Errno::IO));
        }
    }
    Ok(())
}

/// Binds each file of [`HOST_ETC`] the host has into `/etc` of `root`,
/// read-only. The directory becomes read-only with the root.
fn mount_host_etc(root: &OwnedFd) -> Result<(), Failure> {
    let etc = rustix::fs::openat(
        root,
        c"etc",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(fail(Step::Populate))?;
    for (source, name) in HOST_ETC {
        let file = match rustix::mount::open_tree(
            CWD,
            source,
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        ) {
            Ok(file) => file,
            Err(Errno::NOENT) => continue,
            Err(errno) => return Err((Step::MountEtc, errno)),
        };
        sys::mount_setattr(
            file.as_fd(),
            MountAttrFlags::MOUNT_ATTR_RDONLY
                | MountAttrFlags::MOUNT_ATTR_NOSUID
                | MountAttrFlags::MOUNT_ATTR_NODEV
                | MountAttrFlags::MOUNT_ATTR_NOEXEC,
            MountAttrFlags::empty(),
        )
        .map_err(fail(Step::MountEtc))?;
        rustix::fs::openat(
            &etc,
            name,
            OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )
        .map_err(fail(Step::MountEtc))?;
        attach(&file, &etc, name)?;
    }
    Ok(())
}

fn write_proc(path: &CStr, data: &[u8]) -> Result<(), Failure> {
    let file = rustix::fs::open(path, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())
        .map_err(fail(Step::MapIds))?;
    let written = rustix::io::write(&file, data).map_err(fail(Step::MapIds))?;
    if written == data.len() {
        Ok(())
    } else {
        Err((Step::MapIds, Errno::IO))
    }
}

/// The calls of `newuidmap` and `newgidmap` for a caller that is not root,
/// which map the build's own ids and the check user to the caller's first
/// subordinate ids. Fails when a helper is missing from the path or the
/// caller has no subordinate range.
fn helper_calls(uid: u32, gid: u32) -> Result<(HelperCall, HelperCall), Error> {
    let host = crate::check_user_env();
    let missing = |name: &str| {
        Error::new(
            Step::MapIds,
            std::io::Error::other(format!("{name} is not on the path")),
        )
    };
    let Some(newuidmap) = host.newuidmap else {
        return Err(missing("newuidmap"));
    };
    let Some(newgidmap) = host.newgidmap else {
        return Err(missing("newgidmap"));
    };
    let Some(user) = host.user.as_deref() else {
        return Err(Error::new(
            Step::MapIds,
            std::io::Error::other(format!("no /etc/passwd entry for uid {uid}")),
        ));
    };
    let range = |content: &str, file: &str| {
        crate::check_user::first_subordinate(content, user).ok_or_else(|| {
            Error::new(
                Step::MapIds,
                std::io::Error::other(format!("no subordinate id range for {user} in {file}")),
            )
        })
    };
    let subuid = range(&host.subuid, "/etc/subuid")?;
    let subgid = range(&host.subgid, "/etc/subgid")?;
    let number = |value: u32| CString::new(value.to_string()).expect("a number has no nul bytes");
    Ok((
        HelperCall {
            path: cstr(&newuidmap)?,
            args: [
                number(0),
                number(uid),
                number(1),
                number(CHECK_ID),
                number(subuid),
                number(1),
            ],
        },
        HelperCall {
            path: cstr(&newgidmap)?,
            args: [
                number(0),
                number(gid),
                number(1),
                number(CHECK_ID),
                number(subgid),
                number(1),
            ],
        },
    ))
}

/// `path` as a C string.
fn cstr(path: &Path) -> Result<CString, Error> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        Error::new(
            Step::MapIds,
            std::io::Error::other("a path with a nul byte"),
        )
    })
}

/// One id mapping helper forked before the namespace exists: its child,
/// which waits for a byte, and the write end of the pipe that signals it.
struct Helper {
    child: Pid,
    go: OwnedFd,
}

/// Forks one id mapping helper for a process that has not entered its new
/// user namespace yet, so that the setuid bit of the helper program
/// survives: the kernel ignores it for a program that a namespace without
/// maps execs. The helper waits for one byte, then execs the helper
/// program for the process, which by then is its parent inside the
/// namespace.
fn fork_helper(call: &HelperCall) -> Result<Helper, Failure> {
    let (reader, go) = rustix::pipe::pipe_with(PipeFlags::CLOEXEC).map_err(fail(Step::MapIds))?;
    // SAFETY: the helper only reads a pipe, execs or exits, which is safe
    // after fork even when the caller has other threads.
    let child = match unsafe { sys::fork() }.map_err(fail(Step::MapIds))? {
        sys::Fork::Child => {
            drop(go);
            match rustix::io::read(&reader, &mut [0u8; 1]) {
                Ok(1) => exec_helper(call),
                _ => sys::exit(1),
            }
        }
        sys::Fork::Parent(child) => child,
    };
    Ok(Helper { child, go })
}

/// Signals the helper of a process whose namespace now refuses setgroups,
/// and waits for it, which maps that namespace.
fn run_helper(helper: Helper) -> Result<(), Failure> {
    rustix::io::write(&helper.go, &[0u8]).map_err(fail(Step::MapIds))?;
    drop(helper.go);
    match rustix::process::waitpid(Some(helper.child), WaitOptions::empty())
        .map_err(fail(Step::MapIds))?
    {
        Some((_, status)) if status.exit_status() == Some(0) => Ok(()),
        Some((_, status)) if status.exit_status() == Some(127) => Err((Step::MapIds, Errno::NOENT)),
        _ => Err((Step::MapIds, Errno::PERM)),
    }
}

/// Execs the helper `call` for the process that forked this helper.
/// Never returns: a failed exec ends the helper.
fn exec_helper(call: &HelperCall) -> ! {
    let mut argv: [*const libc::c_char; 9] = [std::ptr::null(); 9];
    argv[0] = call.path.as_ptr();
    let mut pid = [0u8; 16];
    let Some(parent) = rustix::process::getppid() else {
        sys::exit(1);
    };
    let pid_raw = u32::try_from(Pid::as_raw(Some(parent))).unwrap_or_default();
    argv[1] = pid_cstr(pid_raw, &mut pid).as_ptr();
    for (slot, arg) in argv[2..].iter_mut().zip(&call.args) {
        *slot = arg.as_ptr();
    }
    // SAFETY: `execv` replaces this helper, which holds a private
    // forked copy of the caller's memory and only close-on-exec
    // descriptors.
    if unsafe { libc::execv(call.path.as_ptr(), argv.as_ptr()) } == -1 {
        sys::exit(127);
    }
    sys::exit(127)
}

/// Writes `pid` as a NUL-terminated decimal C string into `buf`, which
/// must hold at least 12 bytes, without allocating.
fn pid_cstr(pid: u32, buf: &mut [u8; 16]) -> &CStr {
    let mut end = buf.len() - 1;
    buf[end] = 0;
    let mut rest = pid;
    loop {
        end -= 1;
        buf[end] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    CStr::from_bytes_until_nul(&buf[end..]).expect("the digits and the nul byte fit")
}

/// Waits for PID 1 of the sandbox and ends this process the same way.
fn wait_for(init: Pid) -> ! {
    // SAFETY: this process never returns to the standard library. It only
    // waits and exits, so no descriptor is used after this point. Closing
    // them lets the parent see end of file on the command's pipes and the
    // standard library's exec status pipe as soon as the command holds the
    // last copy.
    unsafe { sys::close_all() };
    loop {
        match rustix::process::waitpid(Some(init), WaitOptions::empty()) {
            Ok(Some((_, status))) => sys::exit_like(status),
            Err(Errno::INTR) => {}
            _ => sys::exit(1),
        }
    }
}

pub(crate) fn clone_tree(path: &CStr, attributes: MountAttrFlags) -> Result<OwnedFd, Failure> {
    let tree = rustix::mount::open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .map_err(fail(Step::CloneTree))?;
    sys::mount_setattr(tree.as_fd(), attributes, MountAttrFlags::empty())
        .map_err(fail(Step::SetAttributes))?;
    Ok(tree)
}

pub(crate) fn fresh_mount(
    filesystem: &CStr,
    mode: Option<&CStr>,
    attributes: MountAttrFlags,
) -> Result<OwnedFd, Errno> {
    let context = rustix::mount::fsopen(filesystem, FsOpenFlags::FSOPEN_CLOEXEC)?;
    if let Some(mode) = mode {
        rustix::mount::fsconfig_set_string(&context, c"mode", mode)?;
    }
    rustix::mount::fsconfig_create(&context)?;
    rustix::mount::fsmount(&context, FsMountFlags::FSMOUNT_CLOEXEC, attributes)
}

pub(crate) fn attach(mount: &OwnedFd, parent: &OwnedFd, name: &CStr) -> Result<(), Failure> {
    rustix::mount::move_mount(
        mount,
        c"",
        parent,
        name,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .map_err(fail(Step::Attach))
}

/// Empties the bounding set, so that executing the command as uid 0 grants
/// it no capabilities, and clears the ambient set.
pub(crate) fn drop_capabilities() -> Result<(), Failure> {
    for bit in 0..u64::BITS {
        match rustix::thread::remove_capability_from_bounding_set(CapabilitySet::from_bits_retain(
            1 << bit,
        )) {
            Ok(()) => {}
            // Numbers past the kernel's last capability are rejected.
            Err(Errno::INVAL) => break,
            Err(errno) => return Err((Step::Capabilities, errno)),
        }
    }
    rustix::thread::clear_ambient_capability_set().map_err(fail(Step::Capabilities))
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
