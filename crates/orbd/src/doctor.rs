//! `orbd doctor`: reports whether this host has what the VM runtimes and image
//! preparation need. Prints one line per check; fails if a required check fails.

use crate::config::agent::{DEFAULT_GUEST_HELPER, DEFAULT_GUEST_KERNEL};
use crate::image::{DOCKER_RUN, UMOCI_VERSION};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths to check. Tools default to `PATH`, the guest kernel and helper to where orbd's
/// container image installs them; `--config` takes them from an agent config's
/// `images` and `runtime.qemu` sections.
#[derive(Debug, Default)]
pub struct DoctorOptions {
    pub config: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
}

struct Report {
    failed: bool,
}

impl Report {
    fn line(&mut self, ok: Result<String, String>, what: &str, required: bool) {
        match ok {
            Ok(detail) => println!("ok    {what:<22} {detail}"),
            Err(detail) if required => {
                self.failed = true;
                println!("FAIL  {what:<22} {detail}");
            }
            Err(detail) => println!("warn  {what:<22} {detail}"),
        }
    }
}

fn first_line(program: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let text = if out.stdout.is_empty() {
        out.stderr
    } else {
        out.stdout
    };
    let line = String::from_utf8_lossy(&text)
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    if !out.status.success() && line.is_empty() {
        return Err(format!("{} exited {}", program.display(), out.status));
    }
    Ok(line)
}

fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut len = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        len += n as u64;
        h.update(&buf[..n]);
    }
    Ok((hex::encode(h.finalize()), len))
}

/// The hardware accelerator QEMU orbs need, as named in messages.
pub(crate) const ACCEL_NAME: &str = if cfg!(target_os = "macos") {
    "Hypervisor.framework"
} else {
    "/dev/kvm"
};

/// The hardware accelerator QEMU orbs need works: KVM on Linux, Hypervisor.framework
/// (`kern.hv_support`) on macOS.
pub(crate) fn accel_usable() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    return match orbd_vm::sysctl::u64("kern.hv_support") {
        Some(1) => Ok(()),
        _ => Err("Hypervisor.framework is not supported on this Mac (kern.hv_support)".into()),
    };
    #[cfg(not(target_os = "macos"))]
    kvm_usable()
}

fn accel() -> Result<String, String> {
    #[cfg(target_os = "macos")]
    return accel_usable().map(|()| "kern.hv_support=1 (orbs get no /dev/kvm)".into());
    #[cfg(not(target_os = "macos"))]
    kvm()
}

/// Opens `/dev/kvm` and checks the KVM API version (12).
#[cfg(not(target_os = "macos"))]
pub(crate) fn kvm_usable() -> Result<(), String> {
    // KVM_GET_API_VERSION = _IO(0xAE, 0x00)
    const KVM_GET_API_VERSION: nix::libc::c_ulong = 0xAE00;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("/dev/kvm: {e}"))?;
    // SAFETY: argument-less ioctl on an open /dev/kvm fd.
    let api = unsafe {
        nix::libc::ioctl(
            std::os::fd::AsRawFd::as_raw_fd(&f),
            KVM_GET_API_VERSION as _,
            0,
        )
    };
    if api != 12 {
        return Err(format!("KVM API version {api}, expected 12"));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn kvm() -> Result<String, String> {
    kvm_usable()?;
    Ok("API 12".into())
}

/// Whether the host's KVM nests, so orbs of types with `kvm` can run here (with
/// `ORBD_NESTED_KVM=true`). Optional: no orb gets `/dev/kvm` by default.
#[cfg(not(target_os = "macos"))]
fn nested_kvm() -> Result<String, String> {
    let nested = ["kvm_intel", "kvm_amd"].iter().find_map(|m| {
        let v = std::fs::read_to_string(format!("/sys/module/{m}/parameters/nested")).ok()?;
        Some(format!("{m} nested={}", v.trim()))
    });
    let nested = nested.unwrap_or_else(|| "nested support unknown".into());
    if nested.ends_with("=N") || nested.ends_with("=0") {
        return Err(format!(
            "{nested}: orbs of types with kvm cannot run here (they need a host whose KVM \
             nests, and ORBD_NESTED_KVM=true)"
        ));
    }
    Ok(nested)
}

/// macOS: pf blocks QEMU's network group (`runtime::qemu::fence`), probed as the agent
/// does before starting a QEMU orb.
fn egress_fence(group: Option<&str>) -> Result<String, String> {
    use crate::runtime::qemu::{GROUP_EXEC, check_network_group, fence};
    let group = group.ok_or(
        "runtime.qemu.network_group is not set (pass the agent config with -c): nothing keeps \
         QEMU orbs off the LAN",
    )?;
    let exec = crate::runtime::vm::on_path(Path::new(GROUP_EXEC))
        .ok_or_else(|| format!("{GROUP_EXEC} is not on PATH"))?;
    check_network_group(&exec, group)?;
    fence::probe_for(&exec, group)?.run()?;
    Ok(format!(
        "pf blocks group {group} from 127.0.0.1 ({} setgid {group})",
        exec.display()
    ))
}

fn kernel(path: &Path) -> Result<String, String> {
    let mut header = [0u8; 0x206];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut header))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // arm64 `Image`: magic "ARM\x64" at 0x38; x86 bzImage: "HdrS" at 0x202.
    if cfg!(target_arch = "aarch64") {
        if &header[0x38..0x3c] != b"ARM\x64" {
            return Err(format!("{} is not an arm64 Image", path.display()));
        }
    } else if &header[0x202..0x206] != b"HdrS" {
        return Err(format!("{} is not a bzImage", path.display()));
    }
    let (sha, len) = sha256_file(path)?;
    Ok(format!(
        "{} ({} KiB, sha256 {sha})",
        path.display(),
        len / 1024
    ))
}

fn mke2fs(path: &Path) -> Result<String, String> {
    let line = first_line(path, &["-V"])?;
    // `mke2fs 1.47.0 (5-Feb-2023)`; `-d` with hard links and xattrs needs >= 1.45.
    let version = line.split_whitespace().nth(1).unwrap_or("");
    let parts: Vec<u32> = version.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() < 2 || (parts[0], parts[1]) < (1, 45) {
        return Err(format!("{line}: need e2fsprogs >= 1.45"));
    }
    Ok(line)
}

fn guest_helper(path: &Path) -> Result<String, String> {
    let layer = crate::image::IntegrationLayer::build(path).map_err(|e| e.to_string())?;
    let (sha, len) = sha256_file(path)?;
    Ok(format!(
        "{} ({} KiB, sha256 {sha}; guest integration {})",
        path.display(),
        len / 1024,
        layer.digest
    ))
}

/// Runs the checks; returns false if a required one failed.
pub fn run(opts: &DoctorOptions) -> anyhow::Result<bool> {
    let mut umoci = PathBuf::from("umoci");
    let mut mkfs = PathBuf::from("mkfs.ext4");
    let mut helper = PathBuf::from(DEFAULT_GUEST_HELPER);
    let mut kernel_path = opts.kernel.clone();
    let mut qemu = PathBuf::from(orbd_qemu::probe::QEMU_SYSTEM);
    let mut qemu_img = PathBuf::from("qemu-img");
    let mut firecracker = PathBuf::from("firecracker");
    let mut builder =
        cfg!(target_os = "macos").then(|| crate::config::agent::DEFAULT_IMAGE_BUILDER.to_owned());
    let mut network_group = None;
    if let Some(config) = &opts.config {
        let text = std::fs::read_to_string(config)?;
        let v: serde_json::Value = serde_saphyr::from_str(&text)?;
        let get = |section: &[&str], key: &str| -> Option<PathBuf> {
            let mut t = &v;
            for s in section {
                t = t.get(s)?;
            }
            t.get(key)?.as_str().map(PathBuf::from)
        };
        umoci = get(&["images"], "umoci").unwrap_or(umoci);
        mkfs = get(&["images"], "mkfs_ext4").unwrap_or(mkfs);
        helper = get(&["images"], "guest_helper").unwrap_or(helper);
        kernel_path = kernel_path.or_else(|| get(&["runtime", "qemu"], "kernel"));
        qemu = get(&["runtime", "qemu"], "qemu").unwrap_or(qemu);
        qemu_img = get(&["runtime", "qemu"], "qemu_img").unwrap_or(qemu_img);
        firecracker = get(&["runtime", "firecracker"], "firecracker").unwrap_or(firecracker);
        network_group = get(&["runtime", "qemu"], "network_group").map(|g| g.display().to_string());
        if let Some(b) = get(&["images"], "builder") {
            builder = Some(b.display().to_string());
        }
    }
    let kernel_path = kernel_path.unwrap_or_else(|| DEFAULT_GUEST_KERNEL.into());
    if !nix::unistd::geteuid().is_root() && Path::new(&mkfs).components().count() == 1 {
        // Non-root PATHs often lack /sbin, where e2fsprogs lives.
        if let Some(p) = ["/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4"]
            .iter()
            .find(|p| Path::new(p).exists())
        {
            mkfs = PathBuf::from(p);
        }
    }

    let mut r = Report { failed: false };
    let qemu_check = first_line(&qemu, &["--version"])
        .and_then(|l| orbd_qemu::probe::check_qemu_version(&l).map(|()| l));
    r.line(qemu_check, orbd_qemu::probe::QEMU_SYSTEM, true);
    r.line(first_line(&qemu_img, &["--version"]), "qemu-img", true);
    // Linux only: Firecracker, and the per-orb network namespaces that Firecracker orbs
    // and (on an agent running as root) QEMU orbs get, which need `ip` and `nft`.
    if cfg!(target_os = "linux") {
        r.line(
            first_line(&firecracker, &["--version"]),
            "firecracker",
            false,
        );
        let root = nix::unistd::geteuid().is_root();
        r.line(first_line(Path::new("ip"), &["-V"]), "ip", root);
        r.line(first_line(Path::new("nft"), &["--version"]), "nft", root);
    }
    r.line(accel(), ACCEL_NAME, true);
    #[cfg(not(target_os = "macos"))]
    r.line(nested_kvm(), "nested KVM", false);
    if cfg!(target_os = "macos") {
        // Required unless the agent runs QEMU orbs unfenced on purpose.
        // As the agent's flag reads it: `true` (it refuses anything but true or false).
        let unfenced = std::env::var("ORBD_ALLOW_UNFENCED_EGRESS").is_ok_and(|v| v == "true");
        r.line(
            egress_fence(network_group.as_deref()),
            "egress fence",
            !unfenced,
        );
    }
    r.line(kernel(&kernel_path), "guest kernel", true);
    let umoci_version = |l: String| {
        if l == format!("umoci version {UMOCI_VERSION}") {
            Ok(l)
        } else {
            Err(format!("{l:?}; need umoci {UMOCI_VERSION}"))
        }
    };
    r.line(guest_helper(&helper), "orbd-guest", true);
    // Image building: in the builder container (umoci, mkfs.ext4, root inside it), else
    // with host tools as root.
    if let Some(b) = &builder {
        let args: Vec<&str> = DOCKER_RUN
            .into_iter()
            .chain([b.as_str(), "umoci", "--version"])
            .collect();
        let check = first_line(Path::new("docker"), &args).and_then(umoci_version);
        r.line(check.map(|l| format!("{b}: {l}")), "image builder", true);
        return Ok(!r.failed);
    }
    r.line(
        first_line(&umoci, &["--version"]).and_then(umoci_version),
        "umoci",
        true,
    );
    r.line(mke2fs(&mkfs), "mkfs.ext4", true);
    let privileged = if nix::unistd::geteuid().is_root() {
        Ok("running as root".to_owned())
    } else {
        match Command::new("sudo").args(["-n", "true"]).status() {
            Ok(s) if s.success() => Ok("not root; `sudo -n` works (development only)".into()),
            _ => Err("not root and `sudo -n` fails: image unpacking needs root".into()),
        }
    };
    r.line(privileged, "privileges", true);
    Ok(!r.failed)
}
