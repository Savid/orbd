use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

const DEFAULT_CONFIG: &str = "/etc/orbd/orbd.yaml";

const AFTER_HELP: &str = "\
Operating the fleet (on the coordinator, e.g. `docker exec orbd orbd status`):
  orbd status                 agents, orbs and what needs attention, worst first
  orbd orb list --problems    orbs failing, faulted or stuck
  orbd orb show <orb>         one orb: state, disk, wake check, failures, commands, next steps
  orbd agent list             agents and their capacity

An <orb> is an Amp orb id (amp-<uuid>) or its thread id (T-<uuid>); `orb show` also
takes a unique prefix. Add --json to any of these (and to `orb pause|delete`) for one
JSON object on stdout (fields are only ever added; times are *_unix_ms, sizes *_bytes);
errors then go to stderr as JSON too.";

#[derive(Parser)]
#[command(
    name = "orbd",
    version,
    about = "Self-hosted backend for Amp orbs",
    after_help = format!("{AFTER_HELP}\n\n{}", orbd::cli::EXIT_CODES_HELP)
)]
struct Cli {
    /// Log as JSON lines.
    #[arg(long, global = true, env = "ORBD_LOG_JSON")]
    log_json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct CoordinatorArgs {
    /// Coordinator configuration.
    #[arg(long, short, env = "ORBD_CONFIG", default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

/// Arguments of the operator commands on the coordinator's admin socket.
#[derive(Args)]
struct OperatorArgs {
    /// Print the result as one JSON object on stdout, and errors as one JSON object on
    /// stderr.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    coordinator: CoordinatorArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run the coordinator (wraps one `amp orb provider` per offering).
    Coordinator(CoordinatorArgs),
    /// Run an agent on a compute host (or manage agents: `orbd agent list|remove`).
    #[command(args_conflicts_with_subcommands = true)]
    Agent {
        #[command(subcommand)]
        manage: Option<AgentCommand>,
        #[command(flatten)]
        run: Box<AgentArgs>,
    },
    /// Print a single-use join token for a new agent (run on the coordinator).
    JoinToken {
        /// Id for the new agent, e.g. `host-1`.
        agent_id: String,
        /// Validity in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// URL the agent dials: `public_url` (default) or one of `extra_urls`.
        #[arg(long)]
        url: Option<String>,
        #[command(flatten)]
        coordinator: CoordinatorArgs,
    },
    /// Agents, orbs and what needs attention, worst first (run on the coordinator).
    #[command(after_help = format!(
        "{}\n\n{}",
        orbd::cli::status::PROBLEM_KINDS_HELP,
        orbd::cli::EXIT_CODES_HELP
    ))]
    Status {
        /// Exit 6 when a problem has severity error (after printing).
        #[arg(long)]
        check: bool,
        /// Orbs asleep at least this many days are cleanup candidates, and asleep orbs
        /// not active for as long do not count towards an agent being full.
        #[arg(long, default_value_t = 3)]
        idle_days: u64,
        #[command(flatten)]
        op: OperatorArgs,
    },
    /// Inspect, pause or delete orbs (run on the coordinator).
    #[command(subcommand)]
    Orb(OrbCommand),
    /// Handle one Amp dispatch job from the environment (run by `amp orb provider`).
    Dispatch,
    /// Check host prerequisites (QEMU, KVM or Hypervisor.framework, guest kernel, image tools).
    Doctor {
        /// Agent config to take tool and asset paths from.
        #[arg(long, short, env = "ORBD_AGENT_CONFIG")]
        config: Option<PathBuf>,
        /// Guest kernel (bzImage, or arm64 Image) to check [default: runtime.qemu.kernel,
        /// else /usr/share/orbd/bzImage; on macOS /usr/local/share/orbd/Image].
        #[arg(long)]
        kernel: Option<PathBuf>,
    },
    /// Connects to ADDR with this process's credentials: the agent's egress fence probe,
    /// run through `orbd-netgroup` (internal).
    #[command(hide = true)]
    FenceProbe {
        addr: std::net::SocketAddr,
        /// The group it must run with.
        #[arg(long)]
        gid: u32,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// List enrolled agents (run on the coordinator).
    #[command(after_help = orbd::cli::EXIT_CODES_HELP)]
    List(OperatorArgs),
    /// Revoke an agent for good; its orbs stay recorded on it, unavailable.
    Remove {
        agent_id: String,
        #[command(flatten)]
        coordinator: CoordinatorArgs,
    },
}

#[derive(Subcommand)]
enum OrbCommand {
    /// List orbs, oldest first: state and for how long, agent, type, what they hold on
    /// disk (DISK, of it CKPT the memory checkpoint), and a note when something is wrong
    /// or would be on wake.
    #[command(after_help = orbd::cli::EXIT_CODES_HELP)]
    List {
        /// Only orbs on this agent.
        #[arg(long)]
        agent: Option<String>,
        /// Only orbs in this state.
        #[arg(long, value_parser = ["running", "asleep", "stopped", "deleting", "faulted", "uncreated"])]
        state: Option<String>,
        /// Only orbs asleep (or stopped) for at least this many days.
        #[arg(long)]
        asleep_days: Option<u64>,
        /// Only orbs named by a warning or error of `orbd status`.
        #[arg(long)]
        problems: bool,
        #[command(flatten)]
        op: OperatorArgs,
    },
    /// Show one orb: state, agent, disk use, whether it would wake now and why not,
    /// failures since its last success, its latest commands and Amp requests, and next
    /// steps.
    #[command(after_help = orbd::cli::EXIT_CODES_HELP)]
    Show {
        /// Amp orb id, a unique prefix of one (`amp-01a1e1f8`), or its thread id
        /// (`T-<uuid>`).
        orb: String,
        /// Commands to show, latest first.
        #[arg(long, default_value_t = 20)]
        history: u32,
        #[command(flatten)]
        op: OperatorArgs,
    },
    /// Pause an orb as if Amp had sent `pause` (a memory checkpoint where the runtime
    /// keeps one), after any job Amp has queued for it. For an orb Amp no longer
    /// pauses, e.g. one whose provider token is no longer served; its thread's next
    /// spawn wakes it.
    #[command(after_help = orbd::cli::EXIT_CODES_HELP)]
    Pause {
        /// Amp orb id (`amp-<thread id>`) or thread id (`T-<uuid>`), exactly.
        orb: String,
        #[command(flatten)]
        op: OperatorArgs,
    },
    /// Delete an orb whose thread is gone (Amp sends no delete for an archived thread),
    /// as if Amp had sent `delete`. Refused unless the orb was last seen asleep or
    /// stopped at least `--min-asleep-mins` ago, with no job from Amp open or started
    /// since (the coordinator keeps finished jobs for about an hour), or `--force`. A
    /// later spawn starts a fresh orb.
    #[command(after_help = orbd::cli::EXIT_CODES_HELP)]
    Delete {
        /// Amp orb id (`amp-<thread id>`) or thread id (`T-<uuid>`), exactly.
        orb: String,
        /// How long ago the orb must have been last seen asleep or stopped.
        #[arg(long, default_value_t = 60)]
        min_asleep_mins: u64,
        /// Delete the orb whatever it is doing, stopping it if it runs (its processes
        /// and files are lost), even if its thread is in use, and also an orb whose
        /// earlier delete did not finish. For an orb Amp no longer drives; prefer
        /// `orbd orb pause`, then a plain delete once `--min-asleep-mins` has passed.
        /// Once queued (behind any job Amp has for the orb) it runs even if this command
        /// is interrupted.
        #[arg(long, conflicts_with = "min_asleep_mins")]
        force: bool,
        #[command(flatten)]
        op: OperatorArgs,
    },
}

#[derive(Args)]
struct AgentArgs {
    /// Join token from `orbd join-token`; needed only for the first start.
    #[arg(long, env = "ORBD_JOIN", hide_env_values = true)]
    join: Option<String>,
    /// Dial the coordinator here instead of the URL from enrollment, e.g. one of its
    /// `extra_urls`. Its host must be named on the coordinator's certificate.
    #[arg(long, env = "ORBD_COORDINATOR_URL")]
    coordinator_url: Option<String>,
    #[arg(long, env = "ORBD_STATE_DIR", default_value = "/var/lib/orbd")]
    state_dir: PathBuf,
    /// DNS servers for orbs, comma-separated.
    #[arg(long, env = "ORBD_DNS", value_delimiter = ',', default_values_t = orbd::config::agent::DEFAULT_DNS.map(String::from))]
    dns: Vec<String>,
    /// Private IPv4 network VM orbs see (guest `.15`, gateway `.2`); pick one that the
    /// orbs' own workloads (e.g. Docker networks) do not use. Applies to new orbs.
    #[arg(long, env = "ORBD_GUEST_NETWORK", default_value_t = Default::default())]
    guest_network: orbd::config::agent::GuestNetwork,
    /// Overrides the detected vCPU ceiling.
    #[arg(long, env = "ORBD_CAPACITY_VCPUS")]
    capacity_vcpus: Option<u32>,
    /// Overrides the detected memory ceiling.
    #[arg(long, env = "ORBD_CAPACITY_MEMORY_MIB")]
    capacity_memory_mib: Option<u64>,
    /// Limits what orbs may allocate on disk [default: the filesystem's size].
    #[arg(long, env = "ORBD_CAPACITY_DISK_GIB")]
    capacity_disk_gib: Option<u64>,
    /// Free disk to keep: no orb starts or wakes below it [default: max(10 GiB, 5%)].
    #[arg(long, env = "ORBD_DISK_RESERVE_GIB")]
    disk_reserve_gib: Option<u64>,
    /// Memory to keep available on the host: no orb starts or wakes unless the host's
    /// available memory, less this, holds it [default: max(4 GiB, 10% of memory)].
    #[arg(long, env = "ORBD_MEMORY_RESERVE_GIB")]
    memory_reserve_gib: Option<u64>,
    /// Drop the memory checkpoint of an orb asleep longer than this: it cold-boots on
    /// its next wake (disk kept, processes lost) [default: 0, checkpoints are kept].
    #[arg(long, env = "ORBD_CHECKPOINT_MAX_AGE_HOURS")]
    checkpoint_max_age_hours: Option<u64>,
    /// Prometheus listener, e.g. `127.0.0.1:9465`.
    #[arg(long, env = "ORBD_METRICS_LISTEN")]
    metrics_listen: Option<std::net::SocketAddr>,
    /// Take new orbs only when no other agent fits them, e.g. on a laptop or workstation
    /// that is not always on (orbs stay on the agent they were created on).
    #[arg(long, env = "ORBD_OVERFLOW")]
    overflow: bool,
    /// Private destinations VM orbs may reach, comma-separated
    /// `<tcp|udp|any>:<address or CIDR>[:<port or range>]`, e.g.
    /// `udp:192.168.2.201:41641,tcp:10.0.0.0/8:8000-8100`. Otherwise they reach the
    /// internet only: the LAN, a tailnet's 100.64.0.0/10, loopback, multicast,
    /// documentation and reserved addresses are dropped for them; cloud metadata always
    /// is. Their DNS servers are allowed on port 53.
    #[arg(long, env = "ORBD_EGRESS_ALLOW", value_delimiter = ',')]
    egress_allow: Vec<String>,
    /// Let VM orbs reach every private destination, the host's LAN included (orbd
    /// before 0.2; cloud metadata stays blocked).
    #[arg(long, env = "ORBD_ALLOW_PRIVATE_EGRESS")]
    allow_private_egress: bool,
    /// Jail each VMM on Linux (`on`, `off`): its orb's own uid, no capabilities, only its
    /// orb's files mounted. On, a Linux VM agent must run as root and launches no VMM the
    /// jail cannot hold; `off` runs VMMs unjailed as the agent's user (unsafe; for
    /// development only).
    #[arg(long, env = "ORBD_VMM_JAIL", default_value_t = Default::default())]
    vmm_jail: orbd::config::agent::JailMode,
    /// First uid and gid of jailed VMMs; each orb's VMM gets its own above it.
    #[arg(long, env = "ORBD_VMM_JAIL_UID_BASE", default_value_t = orbd::config::agent::DEFAULT_JAIL_UID_BASE)]
    vmm_jail_uid_base: u32,
    /// Log every new connection an orb in orbd's network namespaces (Firecracker) starts:
    /// one `orbd::flow` event with the orb, its Amp orb and thread, protocol,
    /// destination and whether the egress policy accepted or dropped it.
    #[arg(long, env = "ORBD_FLOW_LOG")]
    flow_log: bool,
    /// Run orbs only in VMs (QEMU, Firecracker), never in Docker containers: start only
    /// if a VM runtime is usable, and refuse a Docker runtime that is configured or that
    /// this agent was set up with.
    #[arg(long, env = "ORBD_VM_ONLY")]
    vm_only: bool,
    /// Give orbs of types with `kvm` their `/dev/kvm` (nested virtualization in QEMU).
    /// `false`: this agent advertises no nested KVM, so the coordinator places no such orb
    /// here, and it refuses to start one itself (e.g. one created here earlier).
    #[arg(
        long,
        env = "ORBD_NESTED_KVM",
        default_value_t = true,
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    nested_kvm: bool,
    /// macOS: start QEMU orbs even when pf does not verifiably block their network group
    /// (`runtime.qemu.network_group`); they then reach whatever the Mac can, its LAN
    /// included.
    #[arg(long, env = "ORBD_ALLOW_UNFENCED_EGRESS")]
    allow_unfenced_egress: bool,
    /// Images this agent prepares and runs, comma-separated: `<repository>` (any tag or
    /// digest), `<repository>:<tag>`, `<repository>@<digest>` or `<registry>/<prefix>*`,
    /// e.g. `us-central1-docker.pkg.dev/amp-prod-0/amp-orb/*`. Spawns of other images
    /// fail, and they are not prewarmed [default: any image].
    #[arg(long, env = "ORBD_IMAGE_ALLOW", value_delimiter = ',')]
    image_allow: Vec<String>,
    /// How Linux agents run umoci and mkfs.ext4 over image content: `on`, as root of a
    /// user namespace that sees nothing else of the host (an agent that cannot build one,
    /// e.g. one not running as root, refuses to start); `off`, as real root (unsafe:
    /// whoever sets an orb's image then feeds root-run tar and ext4 tooling).
    #[arg(long, env = "ORBD_IMAGE_SANDBOX", default_value = "on", value_parser = ["on", "off"])]
    image_sandbox: String,
    /// First of the 65536 host uids and gids the image sandbox maps (its 0..65535);
    /// nothing on the host may use them.
    #[arg(long, env = "ORBD_IMAGE_SANDBOX_UID_BASE", default_value_t = orbd::config::agent::DEFAULT_IMAGE_SANDBOX_UID_BASE)]
    image_sandbox_uid_base: u32,
    /// Optional YAML with advanced runtime and image settings.
    #[arg(long, short, env = "ORBD_AGENT_CONFIG")]
    config: Option<PathBuf>,
}

fn admin_socket(args: &CoordinatorArgs) -> anyhow::Result<PathBuf> {
    Ok(orbd::config::coordinator::CoordinatorConfig::load(&args.config)?.admin_socket())
}

/// The admin socket from the coordinator config, for the operator CLI.
fn socket(args: &CoordinatorArgs) -> Result<PathBuf, orbd::cli::CliError> {
    admin_socket(args).map_err(|e| {
        orbd::cli::CliError::new(orbd::cli::Exit::Failed, format!("{e:#}"))
            .hint("pass the coordinator's config with -c (or ORBD_CONFIG)")
    })
}

/// Runs one operator CLI command: prints its output, or its error (as JSON with
/// `--json`) and exits with the error's code.
fn run_cli(
    rt: &tokio::runtime::Runtime,
    json: bool,
    f: impl std::future::Future<Output = Result<String, orbd::cli::CliError>>,
) -> anyhow::Result<()> {
    match rt.block_on(f) {
        Ok(out) => {
            print!("{out}");
            Ok(())
        }
        Err(e) => {
            e.print(json);
            std::process::exit(e.exit as i32);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind as K;
            let shown = matches!(
                e.kind(),
                K::DisplayHelp | K::DisplayVersion | K::DisplayHelpOnMissingArgumentOrSubcommand
            );
            if !shown && std::env::args().any(|a| a == "--json") {
                let message = e.kind().to_string();
                let detail = e.to_string();
                let detail = detail.lines().next().unwrap_or(&message);
                orbd::cli::CliError::new(
                    orbd::cli::Exit::Usage,
                    detail.trim_start_matches("error: ").to_owned(),
                )
                .hint("`orbd <command> --help`")
                .print(true);
                std::process::exit(orbd::cli::Exit::Usage as i32);
            }
            e.exit()
        }
    };
    if let Command::FenceProbe { addr, gid } = cli.command {
        std::process::exit(orbd::runtime::qemu::fence::probe_main(addr, gid));
    }
    orbd::configure_failpoints();
    let rt = tokio::runtime::Runtime::new()?;
    use orbd::backend::fleet::admin;
    match cli.command {
        Command::Dispatch => {
            // Logs from the coordinator are forwarded verbatim; keep our own quiet.
            let code = rt.block_on(orbd::amp::dispatch::run_from_env());
            std::process::exit(code);
        }
        Command::FenceProbe { .. } => unreachable!("handled above"),
        Command::Doctor { config, kernel } => {
            let ok = orbd::doctor::run(&orbd::doctor::DoctorOptions { config, kernel })?;
            std::process::exit(if ok { 0 } else { 1 });
        }
        Command::JoinToken {
            agent_id,
            ttl_secs,
            url,
            coordinator,
        } => {
            let socket = admin_socket(&coordinator)?;
            let ttl = std::time::Duration::from_secs(ttl_secs);
            println!(
                "{}",
                rt.block_on(admin::cli_join_token(
                    &socket,
                    &agent_id,
                    ttl,
                    url.as_deref()
                ))?
            );
            Ok(())
        }
        Command::Agent {
            manage: Some(AgentCommand::List(op)),
            ..
        } => run_cli(&rt, op.json, async {
            orbd::cli::status::agent_list(&socket(&op.coordinator)?, op.json).await
        }),
        Command::Agent {
            manage:
                Some(AgentCommand::Remove {
                    agent_id,
                    coordinator,
                }),
            ..
        } => rt.block_on(admin::cli_remove(&admin_socket(&coordinator)?, &agent_id)),
        Command::Status {
            check,
            idle_days,
            op,
        } => {
            let t = orbd::cli::status::Thresholds {
                idle: std::time::Duration::from_secs(idle_days.max(1).saturating_mul(86_400)),
                ..Default::default()
            };
            run_cli(&rt, op.json, async {
                let (out, healthy) =
                    orbd::cli::status::status(&socket(&op.coordinator)?, t, op.json).await?;
                if check && !healthy {
                    print!("{out}");
                    return Err(orbd::cli::status::unhealthy());
                }
                Ok(out)
            })
        }
        Command::Orb(OrbCommand::List {
            agent,
            state,
            asleep_days,
            problems,
            op,
        }) => {
            let f = orbd::cli::orbs::ListFilter {
                agent,
                state,
                asleep_for: asleep_days
                    .map(|d| std::time::Duration::from_secs(d.saturating_mul(86_400))),
                problems,
            };
            run_cli(&rt, op.json, async {
                orbd::cli::orbs::list(&socket(&op.coordinator)?, &f, op.json).await
            })
        }
        Command::Orb(OrbCommand::Show { orb, history, op }) => run_cli(&rt, op.json, async {
            orbd::cli::orbs::show(&socket(&op.coordinator)?, &orb, history, op.json).await
        }),
        Command::Orb(OrbCommand::Pause { orb, op }) => run_cli(&rt, op.json, async {
            orbd::cli::orbs::pause(&socket(&op.coordinator)?, &orb, op.json).await
        }),
        Command::Orb(OrbCommand::Delete {
            orb,
            min_asleep_mins,
            force,
            op,
        }) => {
            let min_asleep = (!force)
                .then(|| std::time::Duration::from_secs(min_asleep_mins.saturating_mul(60)));
            run_cli(&rt, op.json, async {
                orbd::cli::orbs::delete(&socket(&op.coordinator)?, &orb, min_asleep, op.json).await
            })
        }
        Command::Coordinator(args) => {
            orbd::telemetry::init_logging(cli.log_json);
            let config = orbd::config::coordinator::CoordinatorConfig::load(&args.config)?;
            rt.block_on(async {
                let shutdown = shutdown_on_signal();
                orbd::coordinator::run(config, shutdown).await
            })
        }
        Command::Agent {
            manage: None,
            run: a,
        } => {
            let a = *a;
            orbd::telemetry::init_logging(cli.log_json);
            let mut config = match &a.config {
                Some(p) => orbd::config::agent::AgentConfig::load(p)?,
                None => Default::default(),
            };
            // Absolute: jailed VMMs resolve the paths of their files from their own root.
            let mut s = orbd::config::agent::AgentSection::new(std::path::absolute(&a.state_dir)?);
            s.dns_servers = a.dns;
            s.guest_network = a.guest_network;
            s.capacity = orbd::config::agent::CapacityOverrides {
                vcpus: a.capacity_vcpus,
                memory_mib: a.capacity_memory_mib,
                disk_gib: a.capacity_disk_gib,
                disk_reserve_gib: a.disk_reserve_gib,
                memory_reserve_gib: a.memory_reserve_gib,
            };
            s.metrics_listen = a.metrics_listen;
            s.coordinator_url = a.coordinator_url;
            s.overflow = a.overflow;
            s.vm_only = a.vm_only;
            s.refuse_nested_kvm = !a.nested_kvm;
            s.allow_unfenced_egress = a.allow_unfenced_egress;
            s.checkpoint_max_age = orbd::config::agent::AgentSection::checkpoint_max_age_hours(
                a.checkpoint_max_age_hours,
            );
            s.egress = orbd::config::agent::Egress::new(a.allow_private_egress, &a.egress_allow)
                .map_err(anyhow::Error::msg)?;
            s.vmm_jail = a.vmm_jail;
            s.vmm_jail_uid_base = a.vmm_jail_uid_base;
            s.egress.flow_log = a.flow_log;
            s.image_allow = orbd::config::agent::ImageAllow::new(&a.image_allow)
                .map_err(|e| anyhow::anyhow!("ORBD_IMAGE_ALLOW: {e}"))?;
            s.image_sandbox = orbd::config::agent::ImageSandbox::new(
                a.image_sandbox == "on",
                a.image_sandbox_uid_base,
            )
            .map_err(anyhow::Error::msg)?;
            // Jailed VMMs and image sandboxes must never share a host uid.
            if let (orbd::config::agent::ImageSandbox::On { uid_base: sb }, false) = (
                s.image_sandbox,
                s.vmm_jail == orbd::config::agent::JailMode::Off,
            ) {
                let jail =
                    u64::from(s.vmm_jail_uid_base)..=u64::from(s.vmm_jail_uid_base) + (1 << 24);
                let sandbox = u64::from(sb)
                    ..u64::from(sb) + u64::from(orbd::config::agent::IMAGE_SANDBOX_IDS);
                if jail.start() < &sandbox.end && &sandbox.start <= jail.end() {
                    anyhow::bail!(
                        "ORBD_VMM_JAIL_UID_BASE ({}..={}) overlaps ORBD_IMAGE_SANDBOX_UID_BASE \
                         ({}..{}): jailed VMMs and image builds must not share host uids",
                        jail.start(),
                        jail.end(),
                        sandbox.start,
                        sandbox.end
                    );
                }
            }
            config.agent = s;
            rt.block_on(async {
                let shutdown = shutdown_on_signal();
                orbd::agent::run(config, a.join, shutdown).await
            })
        }
    }
}

fn shutdown_on_signal() -> CancellationToken {
    let token = CancellationToken::new();
    let t = token.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        tracing::info!("shutdown requested");
        t.cancel();
    });
    token
}
