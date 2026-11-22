//! OCI layout → raw ext4: `umoci raw add-layer` (guest integration), `umoci raw unpack`
//! as root (ownership, modes, xattrs and file capabilities preserved), `mkfs.ext4 -d`
//! into a sparse file. Guest content is only ever read by these tools: nothing is
//! mounted or executed on the host.
//!
//! On Linux each tool runs as root of its own user namespace with nothing of the host but
//! the tools and the paths it works on ([`super::sandbox`]): the image's content never
//! meets real root. The sandbox owns what it writes (the layout, `rootfs/`, the output
//! file while mkfs writes it); orbd's own work directory stays root's, and the output
//! file is handed back before it is published. `ORBD_IMAGE_SANDBOX=off` runs the tools
//! as real root instead (`sudo -n` when orbd is not root), which also unpacks device
//! nodes the sandbox refuses.
//!
//! With a builder image (macOS, which has neither umoci nor a filesystem that keeps
//! Linux ownership and device nodes) the same steps run in one `docker run` of that
//! image: the rootfs is unpacked inside the container and only the work directory
//! (layout, integration layer, output file) is shared with the host.

use super::integration::IntegrationLayer;
use super::registry::{BlobCache, Resolved};
use super::sandbox::{Bind, Sandbox, ro, rw};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// umoci release the pipeline is written and tested against.
pub const UMOCI_VERSION: &str = "0.6.0";
const BASE_TAG: &str = "base";
const ORBD_TAG: &str = "orbd";
const MIB: u64 = 1 << 20;

pub struct Tools {
    pub umoci: PathBuf,
    pub mkfs_ext4: PathBuf,
    /// Docker image with umoci, e2fsprogs and GNU coreutils; set, every step runs in it.
    pub builder: Option<String>,
    /// Without a builder: the sandbox every step runs in; None runs them as real root.
    pub sandbox: Option<Sandbox>,
}

impl Tools {
    /// One step over image content: in the sandbox (which sees only `binds`), or as root
    /// when `privileged` (else as orbd).
    async fn step(
        &self,
        privileged: bool,
        program: &Path,
        args: &[&OsStr],
        binds: &[Bind<'_>],
    ) -> Result<String, String> {
        match &self.sandbox {
            Some(sandbox) => sandbox.run(program, args, binds).await.map_err(explain),
            None => run(privileged, program, args).await,
        }
    }
}

/// Names the image property behind umoci errors the sandbox causes (see
/// [`super::sandbox`]): a user namespace cannot create device nodes, set xattrs only
/// host root may set, or own files beyond its 65536 ids.
fn explain(e: String) -> String {
    let why = if e.contains("mknod: operation not permitted") {
        "the image has a device node, which only real root can create"
    } else if e.contains("restore xattr metadata") && e.contains("operation not permitted") {
        "the image sets an xattr only real root can set (trusted.*, or security.* other \
         than security.capability)"
    } else if e.contains("restore chown metadata") && e.contains("invalid argument") {
        "the image has a file owned by a uid or gid above 65535"
    } else {
        return e;
    };
    format!(
        "{e}\n{why}: the image sandbox does not build it (ORBD_IMAGE_SANDBOX=off would, \
         unsafely, as real root)"
    )
}

/// The pipeline inside a builder container: `$1` work dir, `$2` OCI layout, `$3` output.
/// Sizing is [`sizing`]'s (a test checks they agree). The last stdout line is
/// `size <bytes>`; the rootfs's os-release is left in the work dir as [`OS_RELEASE`].
const BUILDER_SCRIPT: &str = r#"set -euo pipefail
work=$1 layout=$2 out=$3
umoci raw add-layer --image "$layout:base" --tag orbd --no-history "$work/integration.tar"
umoci raw unpack --image "$layout:orbd" /rootfs
for f in usr/lib/os-release etc/os-release; do
  if [ -f "/rootfs/$f" ] && [ ! -L "/rootfs/$f" ]; then cp "/rootfs/$f" "$work/os-release"; break; fi
done
used=$(du -s -x --block-size=1 /rootfs | cut -f1)
files=$(du -s -x --inodes /rootfs | cut -f1)
inodes=$(( files * 2 > used / 16384 ? files * 2 : used / 16384 ))
mib=$((1 << 20))
size=$(( (used + used / 5 + inodes * 256 + 512 * mib + 64 * mib - 1) / (64 * mib) * 64 * mib ))
truncate -s "$size" "$out"
mkfs.ext4 -q -F -t ext4 -L orbd-root -N "$inodes" -E nodiscard -d /rootfs "$out" "$((size / 1024))k"
echo "size $size"
"#;

/// `docker run` of the local builder image (never pulled), without network.
pub(crate) const DOCKER_RUN: [&str; 5] = ["run", "--rm", "--pull=never", "--network", "none"];

/// Inodes and size in bytes of the ext4 image for `used` bytes in `files` files: room for
/// metadata, the journal and first-boot writes before the guest grows the filesystem to
/// the orb's disk size. Inode density follows the image, with the default 16 KiB/inode
/// ratio as a floor so a grown disk keeps enough inodes.
fn sizing(used: u64, files: u64) -> (u64, u64) {
    let inodes = (files * 2).max(used / 16384);
    let size = (used + used / 5 + inodes * 256 + 512 * MIB).div_ceil(64 * MIB) * 64 * MIB;
    (inodes, size)
}

/// Removes the named builder container when dropped before [`Self::done`]: killing
/// `docker run` (a cancelled or timed-out build) leaves its container running.
struct Container(Option<String>);

impl Container {
    fn done(mut self) {
        self.0 = None;
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        if let Some(name) = &self.0 {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Runs a tool, as root via `sudo -n` when orbd itself is not root (development hosts;
/// production agents run as root). Fails with the tool's stderr tail.
async fn run(privileged: bool, program: &Path, args: &[&OsStr]) -> Result<String, String> {
    let mut cmd = if privileged && !nix::unistd::geteuid().is_root() {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(program);
        c
    } else {
        Command::new(program)
    };
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let (r1, r2, status) = tokio::join!(
        stdout.read_to_end(&mut out),
        stderr.read_to_end(&mut err),
        child.wait()
    );
    let status = status.map_err(|e| e.to_string())?;
    let _ = (r1, r2);
    if !status.success() {
        let err = String::from_utf8_lossy(&err);
        let tail: Vec<&str> = err.lines().rev().take(10).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!(
            "{} {} failed ({status}): {}",
            program.display(),
            args.first()
                .map_or(String::new(), |a| a.to_string_lossy().into_owned()),
            tail.join("\n")
        ));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The pinned umoci version, or why the configured binary (or the builder's) is not
/// usable.
pub async fn umoci_version(tools: &Tools) -> Result<String, String> {
    let (out, umoci) = match &tools.builder {
        Some(builder) => {
            let args: Vec<&OsStr> = DOCKER_RUN
                .into_iter()
                .chain([builder.as_str(), "umoci", "--version"])
                .map(OsStr::new)
                .collect();
            (
                run(false, Path::new("docker"), &args).await?,
                builder.clone(),
            )
        }
        None => (
            run(false, &tools.umoci, &[OsStr::new("--version")]).await?,
            tools.umoci.display().to_string(),
        ),
    };
    let version = out
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("umoci version "))
        .unwrap_or("")
        .trim()
        .to_owned();
    if version != UMOCI_VERSION {
        return Err(format!(
            "{umoci} is umoci {version:?}; orbd needs umoci {UMOCI_VERSION}"
        ));
    }
    Ok(version)
}

/// Writes a minimal OCI layout for `resolved` (blobs linked from the cache).
pub fn write_layout(layout: &Path, cache: &BlobCache, resolved: &Resolved) -> Result<(), String> {
    let blobs = layout.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).map_err(|e| e.to_string())?;
    for desc in resolved.blobs() {
        cache.link_into(&desc.digest, layout)?;
    }
    let hex = resolved.manifest_digest.trim_start_matches("sha256:");
    std::fs::write(blobs.join(hex), &resolved.manifest_raw).map_err(|e| e.to_string())?;
    std::fs::write(
        layout.join("oci-layout"),
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )
    .map_err(|e| e.to_string())?;
    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": resolved.manifest_digest,
            "size": resolved.manifest_raw.len(),
            "annotations": {"org.opencontainers.image.ref.name": BASE_TAG},
        }],
    });
    std::fs::write(layout.join("index.json"), index.to_string()).map_err(|e| e.to_string())
}

/// Where the builder container leaves the rootfs's os-release in the work dir.
const OS_RELEASE: &str = "os-release";

/// The distribution of an os-release file: `ID` and `VERSION_ID` (`VERSION_CODENAME`
/// when there is no version, as on Debian testing), e.g. `debian 13`.
fn os_identity(os_release: &str) -> Option<String> {
    let field = |key: &str| {
        os_release.lines().find_map(|l| {
            let v = l.trim().strip_prefix(key)?.strip_prefix('=')?;
            Some(v.trim().trim_matches(['"', '\''])).filter(|v| !v.is_empty())
        })
    };
    let id = field("ID")?;
    let version = field("VERSION_ID").or_else(|| field("VERSION_CODENAME"))?;
    Some(format!("{id} {version}"))
}

/// [`os_identity`] of the first of `candidates` (relative to `root`) that is a regular
/// file reached through directories only: symlinks in an image are never followed on the
/// host, and at most 64 KiB is read.
fn read_os_identity(root: &Path, candidates: &[&str]) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    candidates.iter().find_map(|c| {
        let mut path = root.to_owned();
        let parts: Vec<_> = Path::new(c).components().collect();
        for (i, part) in parts.iter().enumerate() {
            path.push(part);
            let m = std::fs::symlink_metadata(&path).ok()?;
            let last = i + 1 == parts.len();
            if (last && !m.is_file()) || (!last && !m.is_dir()) {
                return None;
            }
        }
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(&path)
            .ok()?;
        if !f.metadata().ok()?.is_file() {
            return None;
        }
        let mut text = String::new();
        f.take(64 * 1024).read_to_string(&mut text).ok()?;
        os_identity(&text)
    })
}

/// Hands the sandbox what it writes: the layout's directories and orbd's own files in
/// it (umoci adds a layer, rewriting the index), and the empty rootfs directory umoci
/// unpacks into. Blobs hard-linked from the cache stay root's, and readable.
fn give_to_sandbox(
    sandbox: &Sandbox,
    layout: &Path,
    rootfs: &Path,
    layer: &Path,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let id = sandbox.host_id(0);
    let chown = |p: &Path| {
        std::os::unix::fs::lchown(p, Some(id), Some(id)).map_err(|e| {
            format!(
                "image sandbox: chown {}: {e} ({})",
                p.display(),
                super::sandbox::HINT
            )
        })
    };
    let readable = |p: &Path, m: &std::fs::Metadata| {
        let mode = m.permissions().mode() & 0o7777;
        if mode & 0o444 == 0o444 {
            return Ok(());
        }
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode | 0o444))
            .map_err(|e| format!("{}: {e}", p.display()))
    };
    let mut dirs = vec![layout.to_owned()];
    while let Some(dir) = dirs.pop() {
        chown(&dir)?;
        for e in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            let m = std::fs::symlink_metadata(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            if m.is_dir() {
                dirs.push(p);
            } else if m.nlink() > 1 {
                readable(&p, &m)?;
            } else {
                chown(&p)?;
            }
        }
    }
    let m = std::fs::metadata(layer).map_err(|e| e.to_string())?;
    readable(layer, &m)?;
    std::fs::create_dir(rootfs).map_err(|e| format!("{}: {e}", rootfs.display()))?;
    std::fs::set_permissions(rootfs, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    chown(rootfs)
}

/// Builds `out` (raw ext4) from the layout plus the integration layer. `work` is a
/// scratch directory that the caller removes (as root: its rootfs is root's or the
/// sandbox's). Returns the image's size and its distribution ([`os_identity`]) when it
/// has an os-release.
pub async fn build(
    tools: &Tools,
    layout: &Path,
    integration: &IntegrationLayer,
    work: &Path,
    out: &Path,
    status: &(dyn Fn(&str) + Sync),
) -> Result<(u64, Option<String>), String> {
    let layer = work.join("integration.tar");
    std::fs::write(&layer, &integration.tar).map_err(|e| e.to_string())?;
    if let Some(builder) = &tools.builder {
        status(&format!("unpacking layers and building ext4 in {builder}"));
        // The work dir is unique per build; it is shared at the same path.
        let name = format!(
            "orbd-build-{}",
            work.file_name().unwrap_or_default().display()
        );
        let mut volume = work.as_os_str().to_owned();
        volume.push(":");
        volume.push(work.as_os_str());
        let mut args: Vec<std::ffi::OsString> = DOCKER_RUN.iter().map(Into::into).collect();
        args.extend(["--name".into(), name.clone().into(), "-v".into(), volume]);
        args.extend([builder, "bash", "-c", BUILDER_SCRIPT, "build"].map(Into::into));
        args.extend([work, layout, out].map(|p| p.as_os_str().to_owned()));
        let args: Vec<&OsStr> = args.iter().map(|a| a.as_os_str()).collect();
        let container = Container(Some(name));
        let stdout = run(false, Path::new("docker"), &args).await?;
        container.done();
        let size = stdout
            .lines()
            .rev()
            .find_map(|l| l.strip_prefix("size ")?.trim().parse().ok())
            .ok_or_else(|| format!("builder printed no size: {stdout:?}"))?;
        return Ok((size, read_os_identity(work, &[OS_RELEASE])));
    }
    let base = format!("{}:{BASE_TAG}", layout.display());
    let rootfs = work.join("rootfs");
    if let Some(sandbox) = &tools.sandbox {
        give_to_sandbox(sandbox, layout, &rootfs, &layer)?;
    }
    status("adding guest integration layer");
    tools
        .step(
            false,
            &tools.umoci,
            &[
                "raw".as_ref(),
                "add-layer".as_ref(),
                "--image".as_ref(),
                base.as_ref(),
                "--tag".as_ref(),
                ORBD_TAG.as_ref(),
                "--no-history".as_ref(),
                layer.as_os_str(),
            ],
            &[rw(layout), ro(&layer)],
        )
        .await?;

    let image = format!("{}:{ORBD_TAG}", layout.display());
    status("unpacking layers");
    tools
        .step(
            true,
            &tools.umoci,
            &[
                "raw".as_ref(),
                "unpack".as_ref(),
                "--image".as_ref(),
                image.as_ref(),
                rootfs.as_os_str(),
            ],
            &[ro(layout), rw(&rootfs)],
        )
        .await?;

    status("sizing root filesystem");
    let du = |flag: &'static str| {
        let rootfs = rootfs.clone();
        async move {
            let out = tools
                .step(
                    true,
                    Path::new("du"),
                    &[
                        "-s".as_ref(),
                        "-x".as_ref(),
                        flag.as_ref(),
                        rootfs.as_os_str(),
                    ],
                    &[ro(&rootfs)],
                )
                .await?;
            out.split_whitespace()
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or_else(|| format!("unexpected du output {out:?}"))
        }
    };
    let os = read_os_identity(&rootfs, &["usr/lib/os-release", "etc/os-release"]);
    let used = du("--block-size=1").await?;
    let files = du("--inodes").await?;
    let (inodes, size) = sizing(used, files);

    status(&format!(
        "building ext4 ({} MiB of files, {files} inodes, {} MiB image)",
        used / MIB,
        size / MIB
    ));
    // Created by orbd so the published file is owned by the agent user, not root (and
    // lent to the sandbox while mkfs writes it).
    let f = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    f.set_len(size).map_err(|e| e.to_string())?;
    let created = lend(tools.sandbox.as_ref(), &f, out)?;
    drop(f);
    let inodes = inodes.to_string();
    let size_kib = format!("{}k", size / 1024);
    tools
        .step(
            true,
            &tools.mkfs_ext4,
            &[
                "-q".as_ref(),
                "-F".as_ref(),
                "-t".as_ref(),
                "ext4".as_ref(),
                "-L".as_ref(),
                "orbd-root".as_ref(),
                "-N".as_ref(),
                inodes.as_ref(),
                "-E".as_ref(),
                "nodiscard".as_ref(),
                "-d".as_ref(),
                rootfs.as_os_str(),
                out.as_os_str(),
                size_kib.as_ref(),
            ],
            &[ro(&rootfs), rw(out)],
        )
        .await?;
    if tools.sandbox.is_some() {
        take_back(out, created, size)?;
    }
    Ok((size, os))
}

/// Lends the output file to the sandbox (its root's, writable by it only); returns its
/// identity.
fn lend(sandbox: Option<&Sandbox>, f: &std::fs::File, out: &Path) -> Result<(u64, u64), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = f.metadata().map_err(|e| e.to_string())?;
    if let Some(sandbox) = sandbox {
        let id = sandbox.host_id(0);
        std::os::unix::fs::fchown(f, Some(id), Some(id)).map_err(|e| {
            format!(
                "image sandbox: chown {}: {e} ({})",
                out.display(),
                super::sandbox::HINT
            )
        })?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    Ok((m.dev(), m.ino()))
}

/// Takes the output file back from the sandbox: still the file orbd created, of the
/// size it gave it, owned by orbd again.
fn take_back(out: &Path, created: (u64, u64), size: u64) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    let m = f.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || (m.dev(), m.ino()) != created || m.len() != size {
        return Err(format!("{}: changed while mkfs.ext4 ran", out.display()));
    }
    std::os::unix::fs::fchown(
        &f,
        Some(nix::unistd::geteuid().as_raw()),
        Some(nix::unistd::getegid().as_raw()),
    )
    .map_err(|e| format!("{}: {e}", out.display()))?;
    f.set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|e| e.to_string())
}

/// Removes a staging directory whose contents may be root-owned.
pub async fn remove_tree(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    // Nothing root-owned lands on macOS hosts (rootfs unpacking runs in the builder).
    if cfg!(not(target_os = "linux")) {
        return std::fs::remove_dir_all(path).map_err(|e| format!("{}: {e}", path.display()));
    }
    run(
        true,
        Path::new("rm"),
        &[
            "-rf".as_ref(),
            "--one-file-system".as_ref(),
            path.as_os_str(),
        ],
    )
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest that lists a layer twice (Amp's image repeats an empty layer) links it
    /// once and leaves the cached blob intact.
    #[test]
    fn a_repeated_layer_keeps_its_cached_blob() {
        use oci_client::manifest::{OciDescriptor, OciImageManifest};
        use sha2::Digest;
        let tmp = tempfile::tempdir().unwrap();
        let cache = BlobCache::new(tmp.path().join("cache"));
        std::fs::create_dir_all(tmp.path().join("cache")).unwrap();
        let blob = |data: &[u8]| {
            let digest = format!("sha256:{}", hex::encode(sha2::Sha256::digest(data)));
            std::fs::write(cache.path(&digest).unwrap(), data).unwrap();
            OciDescriptor {
                digest,
                size: data.len() as i64,
                ..Default::default()
            }
        };
        let (config, empty, other) = (blob(b"{}"), blob(b"empty layer"), blob(b"layer"));
        let resolved = Resolved {
            reference: "example.invalid/amp-orb:latest".parse().unwrap(),
            manifest_digest: format!("sha256:{}", "0".repeat(64)),
            manifest_raw: b"{}".to_vec(),
            manifest: OciImageManifest {
                config,
                layers: vec![empty.clone(), other, empty.clone()],
                ..Default::default()
            },
        };
        assert_eq!(resolved.blobs().count(), 3);
        write_layout(&tmp.path().join("layout"), &cache, &resolved).unwrap();
        assert_eq!(
            std::fs::read(cache.path(&empty.digest).unwrap()).unwrap(),
            b"empty layer"
        );
        // Linking a blob the layout already has is a no-op, never a copy onto itself.
        cache
            .link_into(&empty.digest, &tmp.path().join("layout"))
            .unwrap();
        assert_eq!(
            std::fs::read(cache.path(&empty.digest).unwrap()).unwrap(),
            b"empty layer"
        );
    }

    /// The builder container sizes images with `BUILDER_SCRIPT`'s shell arithmetic, which
    /// must stay [`sizing`].
    #[test]
    fn os_identity_is_the_release_not_the_point_release() {
        let trixie = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nDEBIAN_VERSION_FULL=13.2\nID=debian\n";
        assert_eq!(os_identity(trixie).as_deref(), Some("debian 13"));
        let sid = "PRETTY_NAME=\"Debian GNU/Linux forky/sid\"\nVERSION_CODENAME=forky\nID=debian\n";
        assert_eq!(os_identity(sid).as_deref(), Some("debian forky"));
        let ubuntu = "ID=ubuntu\nID_LIKE=debian\nVERSION_ID='24.04'\nVERSION=\"24.04.1 LTS (Noble Numbat)\"\n";
        assert_eq!(os_identity(ubuntu).as_deref(), Some("ubuntu 24.04"));
        assert_eq!(os_identity("ID_LIKE=debian\nVERSION_ID=1\n"), None);
        assert_eq!(os_identity(""), None);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("real/lib")).unwrap();
        std::fs::write(root.join("real/lib/os-release"), trixie).unwrap();
        std::os::unix::fs::symlink("real/lib/os-release", root.join("link")).unwrap();
        // A symlinked directory on the way (an image's `usr` -> `/` would reach the host).
        std::os::unix::fs::symlink("real", root.join("usr")).unwrap();
        std::fs::create_dir(root.join("fifo-dir")).unwrap();
        nix::unistd::mkfifo(
            &root.join("fifo-dir/os-release"),
            nix::sys::stat::Mode::S_IRWXU,
        )
        .unwrap();
        for not_followed in [
            "link",
            "usr/lib/os-release",
            "fifo-dir/os-release",
            "missing",
        ] {
            assert_eq!(
                read_os_identity(root, &[not_followed]),
                None,
                "{not_followed}"
            );
        }
        assert_eq!(
            read_os_identity(
                root,
                &[
                    "missing",
                    "link",
                    "usr/lib/os-release",
                    "real/lib/os-release"
                ]
            )
            .as_deref(),
            Some("debian 13")
        );
        // Only the start of a huge file is read.
        let mut big = trixie.as_bytes().to_vec();
        big.resize(1 << 20, b'#');
        std::fs::write(root.join("real/big"), &big).unwrap();
        assert_eq!(
            read_os_identity(root, &["real/big"]).as_deref(),
            Some("debian 13")
        );
    }

    #[test]
    fn builder_script_sizes_like_sizing() {
        let arith: Vec<&str> = BUILDER_SCRIPT
            .lines()
            .filter(|l| {
                ["inodes=", "mib=", "size="]
                    .iter()
                    .any(|p| l.starts_with(p))
            })
            .collect();
        for (used, files) in [(4_700_000_000, 160_000), (300 << 20, 9_000)] {
            let script = format!(
                "used={used} files={files}\n{}\necho $inodes $size",
                arith.join("\n")
            );
            let out = std::process::Command::new("bash")
                .args(["-c", &script])
                .output()
                .unwrap();
            let (inodes, size) = sizing(used, files);
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                format!("{inodes} {size}")
            );
        }
    }

    /// One tar entry of a test layer, with PAX xattrs.
    struct Entry<'a> {
        path: &'a str,
        kind: tar::EntryType,
        mode: u32,
        owner: (u64, u64),
        data: &'a [u8],
        link: &'a str,
        xattrs: &'a [(&'a str, &'a [u8])],
    }

    fn entry<'a>(path: &'a str, kind: tar::EntryType, mode: u32) -> Entry<'a> {
        Entry {
            path,
            kind,
            mode,
            owner: (0, 0),
            data: b"",
            link: "",
            xattrs: &[],
        }
    }

    fn layer(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for e in entries {
            if !e.xattrs.is_empty() {
                let mut pax = Vec::new();
                for (k, v) in e.xattrs {
                    let body = format!(" SCHILY.xattr.{k}=").len() + v.len() + 1;
                    let mut len = body + 1;
                    while len.to_string().len() + body != len {
                        len = len.to_string().len() + body;
                    }
                    pax.extend(format!("{len} SCHILY.xattr.{k}=").as_bytes());
                    pax.extend(*v);
                    pax.push(b'\n');
                }
                let mut h = tar::Header::new_ustar();
                h.set_entry_type(tar::EntryType::XHeader);
                h.set_mode(0o644);
                h.set_size(pax.len() as u64);
                b.append_data(&mut h, format!("PaxHeaders/{}", e.path), &pax[..])
                    .unwrap();
            }
            let mut h = tar::Header::new_ustar();
            h.set_entry_type(e.kind);
            h.set_mode(e.mode);
            h.set_uid(e.owner.0);
            h.set_gid(e.owner.1);
            h.set_mtime(1_700_000_000);
            if e.kind == tar::EntryType::Char {
                h.set_device_major(1).unwrap();
                h.set_device_minor(3).unwrap();
            }
            h.set_size(e.data.len() as u64);
            if e.link.is_empty() {
                b.append_data(&mut h, e.path, e.data).unwrap();
            } else {
                h.set_size(0);
                b.append_link(&mut h, e.path, e.link).unwrap();
            }
        }
        b.into_inner().unwrap()
    }

    fn sh(script: &str) {
        let s = std::process::Command::new("sh")
            .args(["-ec", script])
            .status()
            .unwrap();
        assert!(s.success(), "{script}");
    }

    fn debugfs(image: &Path, request: &str) -> String {
        let out = std::process::Command::new("debugfs")
            .args(["-R", request])
            .arg(image)
            .output()
            .unwrap();
        assert!(out.status.success(), "debugfs -R {request:?}");
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Every path of an ext4 image with its type and mode, owner, size, link count,
    /// symlink target and xattrs (from debugfs: nothing is mounted).
    fn listing(image: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut dirs = vec![String::new()];
        while let Some(dir) = dirs.pop() {
            let ls = debugfs(image, &format!("ls -p \"{dir}/\""));
            for line in ls.lines() {
                // /inode/mode/uid/gid/name/size/
                let f: Vec<&str> = line.split('/').collect();
                if f.len() < 7
                    || [".", ".."].contains(&f[5])
                    || (dir.is_empty() && f[5] == "lost+found")
                {
                    continue;
                }
                let path = format!("{dir}/{}", f[5]);
                let stat = debugfs(image, &format!("stat \"{path}\""));
                let links = stat
                    .split("Links: ")
                    .nth(1)
                    .and_then(|l| l.split_whitespace().next())
                    .unwrap_or("?");
                let target = stat
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("Fast link dest: "))
                    .unwrap_or("");
                let xattrs: Vec<&str> = stat
                    .split("Extended attributes:\n")
                    .nth(1)
                    .unwrap_or("")
                    .lines()
                    .take_while(|l| l.starts_with("  "))
                    .map(str::trim)
                    .filter(|l| !l.starts_with("system.data"))
                    .collect();
                out.push(format!(
                    "{path} mode={} uid={} gid={} size={} links={links} {target} [{}]",
                    f[2],
                    f[3],
                    f[4],
                    f[6],
                    xattrs.join("; ")
                ));
                if f[2].starts_with("04") {
                    dirs.push(path);
                }
            }
        }
        out.sort();
        out
    }

    /// The sandboxed pipeline builds what real root's builds: owners, modes (setuid,
    /// setgid, sticky), sizes, hard links, symlinks, FIFOs, whiteouts, xattrs and file
    /// capabilities (v2 as v2, namespaced v3 as v3); and refuses what a user namespace
    /// cannot reproduce (a device node, a `trusted.*` xattr, an owner above 65535) where
    /// root builds it. Needs root, umoci and e2fsprogs (e.g. orbd's container image):
    ///
    /// ```sh
    /// cargo test -p orbd --lib image::rootfs -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "needs root, umoci and e2fsprogs"]
    async fn sandbox_builds_what_root_builds() {
        use tar::EntryType as T;
        let tmp = tempfile::tempdir_in(std::env::var("ORBD_TEST_DIR").unwrap_or("/var/tmp".into()))
            .unwrap();
        let helper = tmp.path().join("orbd-guest");
        std::fs::write(&helper, b"\x7fELF test helper").unwrap();
        let integration = IntegrationLayer::build(&helper).unwrap();

        // cap_net_raw+ep: v2, and v3 for uid 1000 of a user namespace.
        let v2 = [
            1, 0, 0, 2, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut v3 = vec![1, 0, 0, 3];
        v3.extend_from_slice(&v2[4..]);
        v3.extend_from_slice(&1000u32.to_le_bytes());
        let caps_v2: [(&str, &[u8]); 1] = [("security.capability", &v2)];
        let caps_v3: [(&str, &[u8]); 1] = [("security.capability", &v3)];
        let owned = |mut e: Entry<'static>, uid, gid| {
            e.owner = (uid, gid);
            e
        };
        let base: Vec<Entry<'_>> = vec![
            entry("etc/", T::Directory, 0o755),
            entry("usr/", T::Directory, 0o755),
            entry("usr/bin/", T::Directory, 0o755),
            Entry {
                data: b"suid",
                ..entry("usr/bin/sudoish", T::Regular, 0o4755)
            },
            owned(
                Entry {
                    data: b"sgid",
                    ..entry("usr/bin/sgid", T::Regular, 0o2755)
                },
                0,
                42,
            ),
            Entry {
                data: b"ping",
                xattrs: &caps_v2,
                ..entry("usr/bin/pingish", T::Regular, 0o755)
            },
            Entry {
                data: b"ns",
                xattrs: &caps_v3,
                ..entry("usr/bin/nscap", T::Regular, 0o755)
            },
            entry("home/", T::Directory, 0o755),
            owned(entry("home/user/", T::Directory, 0o750), 1000, 1000),
            owned(
                Entry {
                    data: b"hello",
                    xattrs: &[("user.note", b"kept")],
                    ..entry("home/user/file", T::Regular, 0o640)
                },
                1000,
                1000,
            ),
            Entry {
                link: "home/user/file",
                ..entry("home/user/hardlink", T::Link, 0o640)
            },
            Entry {
                link: "../usr/bin/sudoish",
                ..entry("etc/link", T::Symlink, 0o777)
            },
            Entry {
                link: "/nowhere",
                ..entry("etc/abs", T::Symlink, 0o777)
            },
            entry("etc/fifo", T::Fifo, 0o600),
            owned(
                Entry {
                    data: b"x",
                    ..entry("etc/nobody", T::Regular, 0o644)
                },
                65534,
                65534,
            ),
            Entry {
                data: b"gone",
                ..entry("etc/old", T::Regular, 0o644)
            },
            entry("tmp/", T::Directory, 0o1777),
            entry("var/", T::Directory, 0o755),
            entry("var/empty/", T::Directory, 0o555),
        ];
        let upper = vec![
            entry("etc/.wh.old", T::Regular, 0o644),
            owned(
                Entry {
                    data: b"new",
                    ..entry("etc/new", T::Regular, 0o600)
                },
                1000,
                1001,
            ),
        ];
        // Each refused by the sandbox only.
        let device = vec![
            entry("etc/", T::Directory, 0o755),
            entry("etc/null", T::Char, 0o666),
        ];
        let trusted = vec![Entry {
            xattrs: &[("trusted.note", b"x")],
            ..entry("trusted", T::Regular, 0o644)
        }];
        let big_uid = vec![owned(entry("big", T::Regular, 0o644), 70000, 0)];

        let make_layout = |name: &str, layers: &[&[Entry<'_>]]| {
            let dir = tmp.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            let l = dir.join("oci");
            sh(&format!(
                "umoci init --layout {l}; umoci new --image {l}:base",
                l = l.display()
            ));
            for (i, entries) in layers.iter().enumerate() {
                let tar = dir.join(format!("layer{i}.tar"));
                std::fs::write(&tar, layer(entries)).unwrap();
                sh(&format!(
                    "umoci raw add-layer --image {l}:base --tag base --no-history {t} 2>/dev/null",
                    l = l.display(),
                    t = tar.display()
                ));
            }
            dir
        };
        let build_in = |dir: PathBuf, sandboxed: bool| {
            let integration = &integration;
            let work = dir.join(if sandboxed {
                "work-sandbox"
            } else {
                "work-root"
            });
            async move {
                std::fs::create_dir_all(work.join("out")).unwrap();
                sh(&format!(
                    "cp -a {}/oci {}/oci",
                    dir.display(),
                    work.display()
                ));
                let tools = Tools {
                    umoci: "umoci".into(),
                    mkfs_ext4: "mkfs.ext4".into(),
                    builder: None,
                    sandbox: sandboxed.then(|| {
                        Sandbox::new(crate::config::agent::DEFAULT_IMAGE_SANDBOX_UID_BASE)
                    }),
                };
                let out = work.join("out/rootfs.ext4");
                let r = build(&tools, &work.join("oci"), integration, &work, &out, &|_| {}).await;
                r.map(|(size, _)| (size, out))
            }
        };

        let dir = make_layout("image", &[&base, &upper]);
        let (root_size, root_image) = build_in(dir.clone(), false).await.unwrap();
        let (sb_size, sb_image) = build_in(dir, true).await.unwrap();
        assert_eq!(root_size, sb_size);
        let (root_list, sb_list) = (listing(&root_image), listing(&sb_image));
        println!("{}", root_list.join("\n"));
        assert_eq!(root_list, sb_list, "the sandbox built something else");
        for want in [
            "/usr/bin/sudoish mode=104755 uid=0 gid=0",
            "/usr/bin/sgid mode=102755 uid=0 gid=42",
            "/home/user/file mode=100640 uid=1000 gid=1000 size=5 links=2",
            "/tmp mode=041777",
            "/etc/fifo mode=010600",
            "/etc/nobody mode=100644 uid=65534 gid=65534",
            "/etc/new mode=100600 uid=1000 gid=1001",
            "/etc/link mode=120777 uid=0 gid=0 size=18 links=1 \"../usr/bin/sudoish\"",
            "user.note (4) = \"kept\"",
            "security.capability (20) = 01 00 00 02 00 20 00 00",
            "security.capability (24) = 01 00 00 03 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e8 03 00 00",
        ] {
            assert!(
                sb_list.iter().any(|l| l.contains(want)),
                "no {want:?} in\n{}",
                sb_list.join("\n")
            );
        }
        assert!(
            !sb_list.iter().any(|l| l.starts_with("/etc/old ")),
            "whiteout applied"
        );
        // Handed back to orbd; the work tree stays the sandbox's for removal.
        let m = std::fs::metadata(&sb_image).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            (m.uid(), m.mode() & 0o777),
            (nix::unistd::geteuid().as_raw(), 0o644)
        );

        for (name, layers, why) in [
            ("device", &device, "device node"),
            ("trusted", &trusted, "xattr only real root"),
            ("big-uid", &big_uid, "above 65535"),
        ] {
            let dir = make_layout(name, &[layers]);
            build_in(dir.clone(), false)
                .await
                .unwrap_or_else(|e| panic!("{name} as root: {e}"));
            let err = build_in(dir, true).await.unwrap_err();
            println!("{name}: {err}");
            assert!(
                err.contains(why) && err.contains("ORBD_IMAGE_SANDBOX=off"),
                "{name}: {err}"
            );
        }
        sh(&format!("rm -rf {}", tmp.path().display()));
    }
}
