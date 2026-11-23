//! Runtime and capacity detection, for agents started without runtime configuration.
//!
//! Detection probes function, not file existence: usable KVM and QEMU select QEMU,
//! otherwise a Docker daemon that answers selects Docker. The first choice is recorded
//! in `<state_dir>/runtime`; later starts use it or fail, so an agent never abandons its
//! orbs because detection changed. A QEMU agent also runs Firecracker orbs when
//! `firecracker` works (it does in orbd's image); an agent whose orbs need a runtime it
//! no longer has refuses to start (see `executor::recover`).
//!
//! Agents are VM-only by default (`ORBD_VM_ONLY`): detection fails unless QEMU is
//! usable, and a configured or recorded Docker runtime is refused, so an agent never
//! falls back to containers sharing the host's kernel. Docker orbs, however the agent
//! would come to run them, take `ORBD_VM_ONLY=false`.

use crate::config::agent::{
    AgentConfig, DockerRuntimeConfig, FirecrackerRuntimeConfig, QemuRuntimeConfig,
};
use crate::model::{GIB, MIB, Resources, RuntimeKind};
use anyhow::{Context, Result, bail};
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn qemu_usable() -> Result<(), String> {
    crate::doctor::accel_usable()?;
    let qemu = orbd_qemu::probe::QEMU_SYSTEM;
    let out = std::process::Command::new(qemu)
        .arg("--version")
        .output()
        .map_err(|e| format!("{qemu}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{qemu} --version: {}", out.status));
    }
    Ok(())
}

fn firecracker_usable() -> Result<(), String> {
    let out = std::process::Command::new("firecracker")
        .arg("--version")
        .output()
        .map_err(|e| format!("firecracker: {e}"))?;
    if !out.status.success() {
        return Err(format!("firecracker --version: {}", out.status));
    }
    Ok(())
}

async fn docker(config: &DockerRuntimeConfig) -> Result<bollard::Docker, String> {
    let docker = match &config.docker_host {
        Some(h) => bollard::Docker::connect_with_host(h),
        None => bollard::Docker::connect_with_local_defaults(),
    }
    .map_err(|e| e.to_string())?;
    match tokio::time::timeout(PROBE_TIMEOUT, docker.ping()).await {
        Ok(Ok(_)) => Ok(docker),
        Ok(Err(e)) => Err(format!("docker: {e}")),
        Err(_) => Err("docker: no answer within 5s".into()),
    }
}

async fn usable(kind: RuntimeKind) -> Result<(), String> {
    match kind {
        RuntimeKind::Qemu => qemu_usable(),
        RuntimeKind::Docker => docker(&DockerRuntimeConfig::default()).await.map(|_| ()),
        other => Err(format!("{} is never detected", other.as_str())),
    }
}

/// Fills in a runtime when the config names none, and the agent's DNS servers.
pub(crate) async fn runtime(config: &mut AgentConfig) -> Result<()> {
    let vm_only = config.agent.vm_only;
    let r = &mut config.runtime;
    if vm_only && r.docker.is_some() {
        bail!(
            "the agent config enables the Docker runtime (runtime.docker), whose orbs are \
             containers sharing the host's kernel: set ORBD_VM_ONLY=false to run them, or \
             remove runtime.docker"
        );
    }
    if r.fake.is_none() && r.docker.is_none() && r.qemu.is_none() && r.firecracker.is_none() {
        let record = config.agent.state_dir.join("runtime");
        let kind = match std::fs::read_to_string(&record) {
            Ok(s) => {
                let kind = parse_kind(s.trim())
                    .with_context(|| format!("unrecognised runtime in {}", record.display()))?;
                if vm_only && kind == RuntimeKind::Docker {
                    bail!(
                        "this agent runs Docker orbs ({} records docker), containers sharing \
                         the host's kernel: set ORBD_VM_ONLY=false to keep running them, or \
                         delete its orbs and start it with a new state directory to run VM \
                         orbs (it never switches runtime, so its orbs would be lost)",
                        record.display()
                    );
                }
                if let Err(why) = usable(kind).await {
                    bail!(
                        "this agent runs {} orbs but {} is not usable: {why}",
                        kind.as_str(),
                        kind.as_str()
                    );
                }
                kind
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let kind = detect(qemu_usable(), vm_only, || usable(RuntimeKind::Docker)).await?;
                crate::pki::write_private(&record, kind.as_str().as_bytes())?;
                kind
            }
            Err(e) => return Err(e).context(format!("reading {}", record.display())),
        };
        tracing::info!(runtime = kind.as_str(), "using detected runtime");
        match kind {
            RuntimeKind::Docker => {
                r.docker = Some(DockerRuntimeConfig::default());
            }
            RuntimeKind::Qemu => {
                r.qemu = Some(QemuRuntimeConfig::default());
                match firecracker_usable() {
                    Ok(()) => r.firecracker = Some(FirecrackerRuntimeConfig::default()),
                    Err(why) => tracing::info!("firecracker runtime off: {why}"),
                }
            }
            other => bail!("the {} runtime is never detected", other.as_str()),
        }
    }
    let r = &mut config.runtime;
    let jail = if r.qemu.is_some() || r.firecracker.is_some() {
        crate::runtime::vm::jail::settings(config.agent.vmm_jail, config.agent.vmm_jail_uid_base)
            .map_err(anyhow::Error::msg)?
    } else {
        None
    };
    if let Some(d) = &mut r.docker {
        d.dns_servers = config.agent.dns_servers.clone();
    }
    if let Some(q) = &mut r.qemu {
        q.dns_servers = config.agent.dns_servers.clone();
        q.guest_network = config.agent.guest_network;
        q.egress = config.agent.egress.clone();
        q.jail = jail;
        q.refuse_nested_kvm = config.agent.refuse_nested_kvm;
        q.allow_unfenced_egress = config.agent.allow_unfenced_egress;
    }
    if let Some(f) = &mut r.firecracker {
        f.dns_servers = config.agent.dns_servers.clone();
        f.guest_network = config.agent.guest_network;
        f.egress = config.agent.egress.clone();
        f.jail = jail;
    }
    // orbd filters the traffic of VM orbs in their own network namespaces: every VM orb
    // on Linux (macOS orbs are fenced by pf instead).
    let filtered = r.firecracker.is_some() || (cfg!(target_os = "linux") && r.qemu.is_some());
    if !filtered && config.agent.egress != Default::default() {
        tracing::warn!(
            "ORBD_EGRESS_ALLOW / ORBD_FLOW_LOG have no effect: \
             this agent's orbs have no network namespaces of their own"
        );
    }
    // Only amd64 QEMU orbs can have /dev/kvm (Hypervisor.framework does not nest).
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) && config.runtime.qemu.is_some() {
        if config.agent.refuse_nested_kvm {
            tracing::info!(
                "nested KVM off (the default): this agent starts no orb whose type has kvm; \
                 ORBD_NESTED_KVM=true allows them"
            );
        } else {
            tracing::info!(
                "nested KVM on (ORBD_NESTED_KVM=true): orbs whose type has kvm get /dev/kvm"
            );
        }
    }
    Ok(())
}

fn parse_kind(s: &str) -> Option<RuntimeKind> {
    [RuntimeKind::Qemu, RuntimeKind::Docker]
        .into_iter()
        .find(|k| k.as_str() == s)
}

/// QEMU when `qemu` says it is usable, else (unless `vm_only`) Docker if `docker` finds
/// it usable.
async fn detect<F>(
    qemu: Result<(), String>,
    vm_only: bool,
    docker: impl FnOnce() -> F,
) -> Result<RuntimeKind>
where
    F: std::future::Future<Output = Result<(), String>>,
{
    if qemu.is_ok() {
        return Ok(RuntimeKind::Qemu);
    }
    if vm_only {
        let fix = if cfg!(target_os = "macos") {
            "install QEMU (Homebrew's qemu) and put it on the agent's PATH"
        } else {
            "give the agent /dev/kvm (in Docker: --device /dev/kvm)"
        };
        bail!(
            "no usable VM runtime: QEMU needs {} and {} ({}). To run VM orbs, {fix}; or set \
             ORBD_VM_ONLY=false to run Docker orbs, containers sharing the host's kernel",
            crate::doctor::ACCEL_NAME,
            orbd_qemu::probe::QEMU_SYSTEM,
            qemu.err().unwrap_or_default(),
        );
    }
    match docker().await {
        Ok(()) => Ok(RuntimeKind::Docker),
        Err(docker) => bail!(
            "no usable runtime: QEMU needs {} and {} ({}); Docker needs \
             its socket, e.g. -v /var/run/docker.sock:/var/run/docker.sock ({docker})",
            crate::doctor::ACCEL_NAME,
            orbd_qemu::probe::QEMU_SYSTEM,
            qemu.err().unwrap_or_else(|| "usable".into())
        ),
    }
}

/// The capacity ceiling: detected resources minus a reserve for the host, with
/// per-field overrides. Docker orbs are siblings on the Docker host, so its CPUs and
/// memory count; otherwise this process's effective (cgroup-limited) resources do.
pub(crate) async fn capacity(config: &AgentConfig) -> Result<Resources> {
    let o = config.agent.capacity;
    let docker_only = config.runtime.fake.is_none() && config.runtime.docker.is_some();
    let (cpus, memory) = match (&config.runtime.docker, o.vcpus.zip(o.memory_mib)) {
        (_, Some(_)) => (0, 0), // both overridden
        (Some(d), None) if docker_only => {
            let info = docker(d)
                .await
                .map_err(anyhow::Error::msg)?
                .info()
                .await
                .context("docker info")?;
            (
                info.ncpu.unwrap_or(0).max(0) as u64,
                info.mem_total.unwrap_or(0).max(0) as u64,
            )
        }
        _ => (
            std::thread::available_parallelism().map_or(1, |n| n.get() as u64),
            local_memory()?,
        ),
    };
    let (_, disk) = super::disk_stats(config);
    let c = Resources {
        vcpus: o
            .vcpus
            .unwrap_or_else(|| cpus.saturating_sub(1).min(u32::MAX as u64) as u32),
        memory_bytes: o
            .memory_mib
            .map(|m| m.saturating_mul(MIB))
            .unwrap_or_else(|| memory.saturating_sub((2 * GIB).max(memory / 10))),
        // A limit on what orbd allocates; by default the filesystem's size, so only its
        // free space (less a reserve, see `disk_reserve`) limits orbs.
        disk_bytes: o.disk_gib.map(|g| g.saturating_mul(GIB)).unwrap_or(disk),
    };
    if c.vcpus == 0 || c.memory_bytes == 0 || c.disk_bytes == 0 {
        bail!(
            "no capacity for orbs: {} vCPUs, {} MiB memory, {} GiB disk after reserving 1 CPU \
             and max(2 GiB, 10%) memory (filesystem of {}); set ORBD_CAPACITY_VCPUS, \
             ORBD_CAPACITY_MEMORY_MIB or ORBD_CAPACITY_DISK_GIB",
            c.vcpus,
            c.memory_bytes / MIB,
            c.disk_bytes / GIB,
            config.agent.state_dir.display()
        );
    }
    tracing::info!(
        vcpus = c.vcpus,
        memory_mib = c.memory_bytes / MIB,
        disk_gib = c.disk_bytes / GIB,
        "capacity ceiling"
    );
    Ok(c)
}

/// The host's physical memory in bytes.
#[cfg(target_os = "macos")]
pub(crate) fn mem_total() -> Option<u64> {
    orbd_vm::sysctl::u64("hw.memsize")
}

/// Memory the kernel considers available, in bytes: on macOS `kern.memorystatus_level`
/// percent of it (counting compressible and purgeable pages).
#[cfg(target_os = "macos")]
pub(crate) fn mem_available() -> Option<u64> {
    let level = orbd_vm::sysctl::u64("kern.memorystatus_level")?.min(100);
    Some(mem_total()? / 100 * level)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn mem_total() -> Option<u64> {
    meminfo("MemTotal:")
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn mem_available() -> Option<u64> {
    meminfo("MemAvailable:")
}

/// A `/proc/meminfo` field in bytes, e.g. `MemAvailable:`.
#[cfg(not(target_os = "macos"))]
fn meminfo(field: &str) -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix(field))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse::<u64>()
        .ok()
        .map(|kib| kib * 1024)
}

/// Physical memory.
#[cfg(target_os = "macos")]
fn local_memory() -> Result<u64> {
    mem_total().context("reading hw.memsize")
}

/// Physical memory, capped by this process's cgroup limit (v2 or v1).
#[cfg(not(target_os = "macos"))]
fn local_memory() -> Result<u64> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;
    let total = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
        .context("no MemTotal in /proc/meminfo")?
        * 1024;
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let v2 = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| format!("/sys/fs/cgroup{}/memory.max", p.trim_end_matches('/')));
    let limit = [
        v2.as_deref().unwrap_or("/sys/fs/cgroup/memory.max"),
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(p).ok())
    .find_map(|v| v.trim().parse::<u64>().ok());
    Ok(limit.map_or(total, |l| l.min(total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent::AgentSection;

    /// An agent config with the defaults (VM-only).
    fn default_config(dir: &std::path::Path) -> AgentConfig {
        AgentConfig {
            agent: AgentSection::new(dir.to_owned()),
            ..Default::default()
        }
    }

    /// However a config is made (flags, a default, a file), it is VM-only and allows no
    /// nested KVM unless told otherwise.
    #[test]
    fn agents_are_vm_only_without_nested_kvm_by_default() {
        for agent in [AgentSection::new("/s".into()), AgentSection::default()] {
            assert!(agent.vm_only && agent.refuse_nested_kvm);
        }
        assert!(QemuRuntimeConfig::default().refuse_nested_kvm);
        let file: QemuRuntimeConfig = serde_saphyr::from_str("kernel: /k").unwrap();
        assert!(file.refuse_nested_kvm);
    }

    #[tokio::test]
    async fn docker_orbs_take_vm_only_false() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = default_config(dir.path());
        config.runtime.docker = Some(DockerRuntimeConfig::default());
        let e = runtime(&mut config).await.unwrap_err().to_string();
        assert!(
            e.contains("ORBD_VM_ONLY=false") && e.contains("runtime.docker"),
            "{e}"
        );
        // Opting in keeps the configured Docker runtime.
        config.agent.vm_only = false;
        runtime(&mut config).await.unwrap();
        assert!(config.runtime.docker.is_some());
    }

    #[tokio::test]
    async fn a_recorded_docker_runtime_takes_vm_only_false() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("runtime"), "docker").unwrap();
        let mut config = default_config(dir.path());
        let e = runtime(&mut config).await.unwrap_err().to_string();
        assert!(
            e.contains("ORBD_VM_ONLY=false") && e.contains("Docker orbs"),
            "{e}"
        );
        assert!(config.runtime.docker.is_none());
    }

    #[tokio::test]
    async fn detection_falls_back_to_docker_only_when_allowed() {
        let unusable = || Err::<(), String>("no /dev/kvm".into());
        let docker_ok = || async { Ok(()) };
        assert_eq!(
            detect(Ok(()), true, docker_ok).await.unwrap(),
            RuntimeKind::Qemu
        );
        assert_eq!(
            detect(unusable(), false, docker_ok).await.unwrap(),
            RuntimeKind::Docker
        );
        let probed = std::cell::Cell::new(false);
        let e = detect(unusable(), true, || async {
            probed.set(true);
            Ok(())
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("ORBD_VM_ONLY=false") && e.contains("no /dev/kvm"),
            "{e}"
        );
        assert!(!probed.get(), "a VM-only agent never probes Docker");
        let e = detect(unusable(), false, || async { Err("no socket".into()) })
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("no socket"), "{e}");
    }
}
