//! Garbage collection of base disks (VM runtimes). Amp never deletes a project snapshot:
//! it reuses one for at most 72 hours, then names a new `ORB_SNAPSHOT_ID`. Image tags
//! move on to new digests, and each orbd build bakes a new guest integration. So
//! snapshots and prepared images pile up unless the agent deletes them.
//!
//! A project snapshot or prepared image is deleted once no orb on this host is built on
//! it (a QEMU orb's `vm.json` names it: its disk reads through to its base; a
//! Firecracker orb's disk is a standalone copy, so it pins nothing) and nothing has
//! used it for [`IDLE`]. A spawn that creates a disk from it counts as a use, and so
//! does publishing it. The current image of a prewarmed reference is kept. A project
//! snapshot goes sooner when no image here can use it any more (see [`DEAD_IDLE`]), or
//! when Amp moved on to a newer one published from it (see [`SUPERSEDED_IDLE`]).
//! Collection runs at startup, hourly and after every orb delete, under
//! [`crate::runtime::vm::BASES`], so no disk is created from a base while it runs.

use super::{Shared, db};
use crate::runtime::vm::{self, BASES, OrbSize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long an unused base is kept: Amp names a project snapshot for at most 72 hours.
pub const IDLE: Duration = Duration::from_secs(72 * 3600);
/// How long an unused project snapshot is kept once Amp moved on to a newer one
/// published from it (see [`doomed_projects`]). Amp may still name the old one (it keeps
/// one per member on some repositories, which nothing here can tell); an orb it names
/// it for after it went starts from its image.
pub const SUPERSEDED_IDLE: Duration = Duration::from_secs(12 * 3600);
/// How long an unused project snapshot is kept once its lineage is none of those the
/// images here resolve to ([`vm::initial_source`] passes it over for each of them). A
/// publication counts as a use, so the hour also keeps one from going before the pause
/// that published it has recorded it.
pub const DEAD_IDLE: Duration = Duration::from_secs(3600);
/// How long every image's lineage must have held before snapshots of other lineages
/// count as dead: an image pushed by mistake, or an orbd upgrade that changes the guest
/// lineage, rolled back within it keeps the projects' snapshots. Half a day leaves time
/// to notice and roll back, against the 72 hours they would otherwise wait.
pub const LINEAGE_SETTLE: Duration = Duration::from_secs(12 * 3600);
const EVERY: Duration = Duration::from_secs(3600);

/// Collects now, then hourly and whenever an orb was deleted, until shutdown.
pub(super) async fn run_loop(sh: Arc<Shared>) {
    loop {
        collect(&sh).await;
        tokio::select! {
            _ = sh.shutdown.cancelled() => break,
            _ = tokio::time::sleep(EVERY) => {}
            _ = sh.orb_deleted.notified() => {}
        }
    }
}

async fn collect(sh: &Arc<Shared>) {
    let state = sh.config.agent.state_dir.clone();
    if !state.join("orbs").is_dir() {
        return; // No VM runtime has run here.
    }
    // Under the lock, doomed bases are only renamed into the trash; deleting them (some
    // GiB each) waits until disk creation may go on.
    let bases = BASES.write().await;
    // Only a publication the agent recorded counts as evidence that a snapshot replaced
    // its parent; without the records, none does.
    let recorded: HashSet<String> = match sh.db.call(|c| db::list_project_snapshots(c)).await {
        Ok(keys) => keys.into_iter().collect(),
        Err(e) => {
            tracing::warn!(error = %e, "garbage collection: listing project snapshots");
            HashSet::new()
        }
    };
    let found = {
        let (state, images) = (state.clone(), sh.images.clone());
        tokio::task::spawn_blocking(move || {
            let in_use = orb_bases(&state)?;
            let lineages = images
                .as_ref()
                .and_then(|s| s.current_lineages(IDLE, LINEAGE_SETTLE));
            let doomed = doomed_projects(
                &state,
                &in_use,
                lineages.as_ref(),
                &recorded,
                SystemTime::now(),
            );
            let images = match &images {
                Some(store) => {
                    let keys = in_use
                        .iter()
                        .filter_map(|b| b.strip_prefix("images/"))
                        .map(str::to_owned)
                        .collect();
                    store.collect_garbage(&keys, IDLE)
                }
                None => Vec::new(),
            };
            Ok::<_, String>((doomed, images))
        })
        .await
    };
    let (doomed, images) = match found {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::warn!("garbage collection skipped: {e}");
            return;
        }
        Err(e) => {
            tracing::warn!("garbage collection failed: {e}");
            return;
        }
    };
    // Forgotten first, so the agent never records (or tells the coordinator it holds) a
    // snapshot that is gone; one forgotten but not moved (a crash between) is still
    // collected later.
    let mut forgotten = Vec::new();
    for d in doomed {
        let key = d.key.clone();
        match sh
            .db
            .call(move |c| db::forget_project_snapshot(c, &key))
            .await
        {
            Ok(()) => forgotten.push(d),
            Err(e) => tracing::warn!(error = %e, "forgetting a project snapshot; keeping it"),
        }
    }
    sh.snapshots_deleted(forgotten.iter().map(|d| d.key.clone()));
    let projects = {
        let state = state.clone();
        tokio::task::spawn_blocking(move || trash_projects(&state, forgotten))
            .await
            .unwrap_or_default()
    };
    drop(bases);

    let mut trashed: Vec<_> = projects
        .iter()
        .map(|p| p.trashed.clone())
        .chain(images.iter().map(|(_, t)| t.clone()))
        .collect();
    if let Some(store) = sh.images.clone() {
        trashed.extend(
            tokio::task::spawn_blocking(move || store.collect_blobs(IDLE))
                .await
                .unwrap_or_default(),
        );
    }
    let removed = tokio::task::spawn_blocking(move || {
        for t in &trashed {
            if let Err(e) = vm::fsutil::remove(t) {
                tracing::warn!(path = %t.display(), error = %e, "deleting from the trash");
            }
        }
    })
    .await;
    if let Err(e) = removed {
        tracing::warn!("garbage collection failed: {e}");
    }
    let projects_for = |why: Why| {
        projects
            .iter()
            .filter(|p| p.why == why)
            .map(|p| p.key.clone())
            .collect::<Vec<_>>()
    };
    for why in [Why::Idle, Why::Superseded, Why::DeadLineage] {
        metrics::counter!("orbd_project_snapshots_deleted_total", "reason" => why.label())
            .increment(projects.iter().filter(|p| p.why == why).count() as u64);
    }
    if !projects.is_empty() || !images.is_empty() {
        tracing::info!(
            projects = ?projects_for(Why::Idle),
            superseded_projects = ?projects_for(Why::Superseded),
            dead_lineage_projects = ?projects_for(Why::DeadLineage),
            images = ?images.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            "deleted project snapshots and images no orb is built on: unused for {}h, \
             superseded and unused for {}h, or of a lineage no image here has and unused \
             for {}h",
            IDLE.as_secs() / 3600,
            SUPERSEDED_IDLE.as_secs() / 3600,
            DEAD_IDLE.as_secs() / 3600,
        );
    }
}

/// Every base directory (`images/<key>`, `projects/<key>`) an orb in `<state>/orbs`
/// is built on (QEMU orbs only). Fails, so nothing is deleted, if any orb's recipe cannot be read.
fn orb_bases(state: &Path) -> Result<HashSet<String>, String> {
    let dir = state.join("orbs");
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut bases = HashSet::new();
    for e in entries {
        let e = e.map_err(|e| format!("{}: {e}", dir.display()))?;
        if crate::model::OrbId::parse(&e.file_name().to_string_lossy()).is_err() {
            continue;
        }
        let path = e.path().join("vm.json");
        let json = match std::fs::read(&path) {
            Ok(j) => j,
            // Deleted since the listing (orb deletes do not wait for this lock).
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !e.path().exists() => {
                continue;
            }
            Err(err) => return Err(format!("{}: {err}", path.display())),
        };
        let found = crate::runtime::qemu::recipe_bases(&json)
            .or_else(|| crate::runtime::firecracker::recipe_bases(&json))
            .ok_or_else(|| format!("{}: not a recipe this agent knows", path.display()))?;
        bases.extend(found);
    }
    Ok(bases)
}

/// Why a project snapshot was deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Why {
    /// Unused for [`IDLE`].
    Idle,
    /// Superseded and unused for [`SUPERSEDED_IDLE`].
    Superseded,
    /// Of a lineage no image here has, and unused for [`DEAD_IDLE`].
    DeadLineage,
}

impl Why {
    fn label(self) -> &'static str {
        match self {
            Why::Idle => "idle",
            Why::Superseded => "superseded",
            Why::DeadLineage => "dead_lineage",
        }
    }
}

/// A project snapshot to delete.
#[derive(Debug)]
struct Doomed {
    key: String,
    path: PathBuf,
    why: Why,
}

/// A project snapshot moved into the trash.
#[derive(Debug)]
struct Trashed {
    key: String,
    trashed: PathBuf,
    why: Why,
}

/// What a project snapshot's `meta.json` says about it.
#[derive(Debug, Default, PartialEq)]
struct Meta {
    /// The image lineage it descends from.
    lineage: Option<String>,
    /// The snapshot its source orb's disk was created from (None: an image, or not known).
    parent: Option<String>,
    /// When it was published.
    created: Option<SystemTime>,
    /// Its source orb's size (None: not known).
    size: Option<OrbSize>,
}

/// Reads a project snapshot's `meta.json`. A missing or unparsable one says nothing
/// (no lineage); any other error is Err, and the snapshot is only collected once idle.
/// Snapshots published before parents and sizes were recorded take them from their
/// source orb's recipe while that orb is here.
fn read_meta(state: &Path, dir: &Path) -> std::io::Result<Meta> {
    let bytes = match std::fs::read(dir.join("meta.json")) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Meta::default()),
        Err(e) => return Err(e),
    };
    let Ok(meta) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(Meta::default());
    };
    let str_of = |k: &str| meta.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    let origin = || {
        let orb = str_of("source_orb").filter(|o| crate::model::OrbId::parse(o).is_ok())?;
        let json = std::fs::read(state.join("orbs").join(orb).join("vm.json")).ok()?;
        crate::runtime::qemu::recipe_origin(&json)
            .or_else(|| crate::runtime::firecracker::recipe_origin(&json))
    };
    let recorded_size = meta
        .get("size")
        .and_then(|v| serde_json::from_value::<OrbSize>(v.clone()).ok());
    let (parent, size) = match (meta.get("parent"), recorded_size) {
        (Some(p), Some(size)) => (p.as_str().map(str::to_owned), Some(size)),
        (recorded, size) => {
            let o = origin();
            (
                match recorded {
                    Some(p) => p.as_str().map(str::to_owned),
                    None => o.as_ref().and_then(|o| o.project.clone()),
                },
                size.or(o.map(|o| o.size)),
            )
        }
    };
    Ok(Meta {
        lineage: str_of("lineage"),
        parent,
        created: meta
            .get("created_unix_ms")
            .and_then(|v| v.as_u64())
            .map(|ms| UNIX_EPOCH + Duration::from_millis(ms)),
        size,
    })
}

/// The project snapshots to delete, none of them in `in_use`:
/// - unused for [`IDLE`];
/// - dead: with `lineages` (see [`crate::image::ImageStore::current_lineages`]) known,
///   of none of them (or of no recorded lineage), and unused for [`DEAD_IDLE`];
/// - superseded and unused for [`SUPERSEDED_IDLE`]. P is superseded by C when C was
///   published later from an orb created from P, of P's size, and nothing used P since;
///   C stays (it is not deleted here, nor dead), was recorded (`recorded`), and was used
///   since its publication (Amp names it).
fn doomed_projects(
    state: &Path,
    in_use: &HashSet<String>,
    lineages: Option<&HashSet<String>>,
    recorded: &HashSet<String>,
    now: SystemTime,
) -> Vec<Doomed> {
    struct Snap {
        key: String,
        path: PathBuf,
        /// None: unreadable; only the idle rule applies.
        meta: Option<Meta>,
        last_used: SystemTime,
        marked_used: Option<SystemTime>,
        dead: bool,
    }
    let mut snaps = Vec::new();
    for e in std::fs::read_dir(state.join("projects"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let (key, path) = (e.file_name().to_string_lossy().into_owned(), e.path());
        let last_used = match vm::last_used(&path) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(key, error = %e, "garbage collection: no use time; keeping it");
                continue;
            }
        };
        let meta = match read_meta(state, &path) {
            Ok(m) => Some(m),
            Err(e) => {
                tracing::warn!(key, error = %e, "garbage collection: unreadable meta.json");
                None
            }
        };
        let dead = match (&meta, lineages) {
            (Some(m), Some(ls)) => m.lineage.as_ref().is_none_or(|l| !ls.contains(l)),
            _ => false,
        };
        snaps.push(Snap {
            marked_used: vm::marked_used(&path),
            key,
            path,
            meta,
            last_used,
            dead,
        });
    }
    let unused = |s: &Snap| now.duration_since(s.last_used).unwrap_or_default();
    let mut doomed: HashMap<&str, Why> = HashMap::new();
    for s in &snaps {
        if in_use.contains(&format!("projects/{}", s.key)) {
            continue;
        }
        if unused(s) >= IDLE {
            doomed.insert(&s.key, Why::Idle);
        } else if s.dead && unused(s) >= DEAD_IDLE {
            doomed.insert(&s.key, Why::DeadLineage);
        }
    }
    let by_key: HashMap<&str, &Snap> = snaps.iter().map(|s| (s.key.as_str(), s)).collect();
    let superseded: HashSet<&str> = snaps
        .iter()
        .filter(|c| !c.dead && !doomed.contains_key(c.key.as_str()))
        .filter(|c| recorded.contains(&c.key))
        .filter_map(|c| {
            let cm = c.meta.as_ref()?;
            let created = cm.created?;
            // Used since it was published: Amp names it.
            c.marked_used.filter(|t| *t > created)?;
            let p = by_key.get(cm.parent.as_deref()?)?;
            let pm = p.meta.as_ref()?;
            let later = pm.created.is_some_and(|t| t < created);
            let unused_since = p.last_used < created;
            let same_size = cm.size.is_some() && cm.size == pm.size;
            (later && unused_since && same_size).then_some(p.key.as_str())
        })
        .collect();
    for s in &snaps {
        if superseded.contains(s.key.as_str())
            && !doomed.contains_key(s.key.as_str())
            && !in_use.contains(&format!("projects/{}", s.key))
            && unused(s) >= SUPERSEDED_IDLE
        {
            doomed.insert(&s.key, Why::Superseded);
        }
    }
    snaps
        .iter()
        .filter_map(|s| {
            Some(Doomed {
                why: *doomed.get(s.key.as_str())?,
                key: s.key.clone(),
                path: s.path.clone(),
            })
        })
        .collect()
}

/// Moves `doomed` into the trash; returns where each one went.
fn trash_projects(state: &Path, doomed: Vec<Doomed>) -> Vec<Trashed> {
    let mut trashed = Vec::new();
    for d in doomed {
        match vm::fsutil::move_to_trash(&d.path, &state.join("trash")) {
            Ok(Some(t)) => trashed.push(Trashed {
                key: d.key,
                trashed: t,
                why: d.why,
            }),
            Ok(None) => {}
            Err(e) => {
                let key = &d.key;
                tracing::warn!(key, error = %e, "deleting an unused project snapshot");
            }
        }
    }
    trashed
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);
    const SIZE: OrbSize = OrbSize {
        vcpus: 2,
        memory_bytes: 1 << 31,
    };

    fn ago(path: &Path, by: Duration) {
        let t = SystemTime::now() - by;
        std::fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    fn unix_ms(by: Duration) -> u64 {
        (SystemTime::now() - by)
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// A project snapshot `key` published `published` ago with `meta` (to which its
    /// `created_unix_ms` is added unless given), last marked used `used` ago.
    fn snapshot(
        state: &Path,
        key: &str,
        mut meta: serde_json::Value,
        published: Duration,
        used: Option<Duration>,
    ) {
        let dir = state.join("projects").join(key);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(m) = meta.as_object_mut() {
            m.entry("created_unix_ms")
                .or_insert_with(|| unix_ms(published).into());
        }
        std::fs::write(dir.join("meta.json"), meta.to_string()).unwrap();
        if let Some(used) = used {
            vm::mark_used(&dir);
            ago(&dir.join("last_used"), used);
        }
        ago(&dir, published);
    }

    /// A snapshot of lineage "new" published with `parent` from an orb of `size`.
    fn child(parent: Option<&str>, size: OrbSize) -> serde_json::Value {
        serde_json::json!({"lineage": "new", "parent": parent, "size": size})
    }

    /// An orb directory `n` with `recipe` as its `vm.json`; returns the orb id.
    fn orb(state: &Path, n: u8, recipe: String) -> String {
        let id = format!("01a17b00-0000-7000-8000-0000000000{n:02}");
        let dir = state.join("orbs").join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vm.json"), recipe).unwrap();
        id
    }

    /// What collection would delete, sorted, with why.
    fn doomed(state: &Path, lineages: Option<&[&str]>, recorded: &[&str]) -> Vec<(String, Why)> {
        let in_use = orb_bases(state).unwrap();
        let lineages: Option<HashSet<String>> =
            lineages.map(|l| l.iter().map(|s| s.to_string()).collect());
        let recorded: HashSet<String> = recorded.iter().map(|s| s.to_string()).collect();
        let mut d: Vec<_> = doomed_projects(
            state,
            &in_use,
            lineages.as_ref(),
            &recorded,
            SystemTime::now(),
        )
        .into_iter()
        .map(|d| (d.key, d.why))
        .collect();
        d.sort_by(|a, b| a.0.cmp(&b.0));
        d
    }

    fn of(keys: &[(&str, Why)]) -> Vec<(String, Why)> {
        keys.iter().map(|(k, w)| (k.to_string(), *w)).collect()
    }

    /// A QEMU orb's `vm.json` as the runtime writes it, built on `base` (`images/<key>`
    /// or `projects/<key>`).
    fn qemu_recipe(state: &Path, base: &str) -> String {
        let (kind, key) = base.split_once('/').unwrap();
        let (source, file) = match kind {
            "images" => (
                serde_json::json!({"kind": "image", "image_ref": "r", "key": key, "manifest_digest": "d"}),
                "rootfs.ext4",
            ),
            _ => (
                serde_json::json!({"kind": "project_snapshot", "key": key}),
                "disk.raw",
            ),
        };
        serde_json::json!({
            "orb": crate::model::OrbId::generate(),
            "vcpus": 2, "memory_bytes": 1u64 << 31, "disk_bytes": 1u64 << 32,
            "base": {
                "source": source.to_string(),
                "path": state.join(base).join(file),
                "size": 1, "inode": 1, "mtime_ns": 1,
            },
            "net": {"backend": {"kind": "user"}, "mac": "m", "ipv4_cidr": "c",
                    "ipv4_gateway": "g", "mtu": 1500},
            "created_unix_ms": 1,
        })
        .to_string()
    }

    /// A Firecracker orb's `vm.json` as the runtime writes it, copied from `base`.
    fn firecracker_recipe(base: &str) -> String {
        let (kind, key) = base.split_once('/').unwrap();
        let source = match kind {
            "images" => {
                serde_json::json!({"kind": "image", "image_ref": "r", "key": key, "manifest_digest": "d"})
            }
            _ => serde_json::json!({"kind": "project_snapshot", "key": key}),
        };
        let orb = crate::model::OrbId::generate();
        serde_json::json!({
            "orb": orb,
            "vcpus": 2, "memory_bytes": 1u64 << 31, "disk_bytes": 1u64 << 32,
            "source": source,
            "net": {"backend": {"kind": "tap", "netns": format!("orbd-{orb}"), "index": 1},
                    "mac": "m", "ipv4_cidr": "c", "ipv4_gateway": "g", "mtu": 1500},
            "created_unix_ms": 1,
        })
        .to_string()
    }

    /// A Firecracker orb's disk is a standalone copy: the base it was copied from goes
    /// once idle, like one no orb was ever built on; deleting moves it into the trash.
    #[test]
    fn firecracker_orbs_pin_no_base() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        orb(state, 0, firecracker_recipe("projects/copied"));
        orb(state, 1, firecracker_recipe("images/k1"));
        snapshot(state, "copied", serde_json::json!({}), 96 * HOUR, None);

        let in_use = orb_bases(state).unwrap();
        assert!(in_use.is_empty(), "{in_use:?}");
        let d = doomed_projects(state, &in_use, None, &HashSet::new(), SystemTime::now());
        let trashed = trash_projects(state, d);
        assert_eq!(trashed.len(), 1);
        assert_eq!(
            (trashed[0].key.as_str(), trashed[0].why),
            ("copied", Why::Idle)
        );
        assert!(
            trashed[0].trashed.join("meta.json").is_file(),
            "moved, not deleted"
        );
        assert!(!state.join("projects/copied").exists());
    }

    /// Only a project snapshot that no orb is built on and nothing used for the idle
    /// time is deleted; an orb recipe that cannot be read stops all deletion.
    #[test]
    fn deletes_only_unused_idle_project_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        orb(state, 0, qemu_recipe(state, "projects/built-on"));
        orb(state, 1, qemu_recipe(state, "images/k1"));
        let none = serde_json::json!({});
        snapshot(state, "built-on", none.clone(), 96 * HOUR, None);
        snapshot(state, "idle", none.clone(), 96 * HOUR, None);
        snapshot(state, "fresh", none.clone(), HOUR, None);
        snapshot(state, "used-lately", none, 96 * HOUR, Some(HOUR));

        assert_eq!(
            orb_bases(state).unwrap(),
            HashSet::from(["projects/built-on".to_owned(), "images/k1".to_owned()])
        );
        assert_eq!(doomed(state, None, &[]), of(&[("idle", Why::Idle)]));

        let broken = state.join("orbs/01a17b00-0000-7000-8000-000000000009");
        std::fs::create_dir_all(&broken).unwrap();
        assert!(
            orb_bases(state).is_err(),
            "an orb directory without vm.json"
        );
        std::fs::write(broken.join("vm.json"), b"{").unwrap();
        assert!(orb_bases(state).is_err(), "an unreadable vm.json");
    }

    /// With the current lineages known, a snapshot of none of them (or of no recorded
    /// lineage, or with a meta.json that does not parse) goes once unused for an hour,
    /// unless a QEMU orb is built on it or its meta.json cannot be read; with them not
    /// known, only idle ones go.
    #[test]
    fn dead_lineage_snapshots_go_after_an_hour() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        orb(state, 1, qemu_recipe(state, "projects/old-built-on"));
        let old = serde_json::json!({"lineage": "old"});
        snapshot(state, "old-built-on", old.clone(), 2 * HOUR, None);
        snapshot(state, "old-unused", old.clone(), 2 * HOUR, None);
        snapshot(
            state,
            "old-just-published",
            old,
            Duration::from_secs(600),
            None,
        );
        snapshot(state, "unrecorded", serde_json::json!({}), 2 * HOUR, None);
        snapshot(
            state,
            "current",
            serde_json::json!({"lineage": "new"}),
            2 * HOUR,
            None,
        );
        let garbled = state.join("projects/garbled");
        std::fs::create_dir_all(&garbled).unwrap();
        std::fs::write(garbled.join("meta.json"), b"{not json").unwrap();
        ago(&garbled, 2 * HOUR);
        // meta.json a directory: reading it fails, not with NotFound.
        let unreadable = state.join("projects/unreadable");
        std::fs::create_dir_all(unreadable.join("meta.json")).unwrap();
        ago(&unreadable, 2 * HOUR);

        assert_eq!(
            doomed(state, None, &[]),
            [],
            "lineages not known: nothing is dead"
        );
        assert_eq!(
            doomed(state, Some(&["new"]), &[]),
            of(&[
                ("garbled", Why::DeadLineage),
                ("old-unused", Why::DeadLineage),
                ("unrecorded", Why::DeadLineage),
            ])
        );
        assert_eq!(
            doomed(state, Some(&["new", "old"]), &[]),
            of(&[
                ("garbled", Why::DeadLineage),
                ("unrecorded", Why::DeadLineage)
            ]),
            "a lineage one image has is alive"
        );
        ago(&unreadable, 96 * HOUR);
        assert!(
            doomed(state, Some(&["new"]), &[]).contains(&("unreadable".into(), Why::Idle)),
            "the idle rule still applies"
        );
    }

    /// P is superseded by C (and goes once unused for 12 hours) only when C was published
    /// from an orb created from P, later than P, of P's size, nothing used P since, and
    /// C stays, was recorded and was used since its publication.
    #[test]
    fn superseded_needs_a_later_adopted_child_of_its_size() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        std::fs::create_dir_all(state.join("orbs")).unwrap();
        let image = || child(None, SIZE);
        let big = OrbSize {
            vcpus: 8,
            memory_bytes: 1 << 34,
        };
        // P published 40h ago, last used (an orb created from it) 30h ago; C published
        // from that orb 29h ago, named since (used 1h ago).
        let family = |p: &str, c: &str, p_used: Duration, c_meta: serde_json::Value, c_used| {
            snapshot(state, p, image(), 40 * HOUR, Some(p_used));
            snapshot(state, c, c_meta, 29 * HOUR, c_used);
        };
        family("p", "c", 30 * HOUR, child(Some("p"), SIZE), Some(HOUR));
        // Amp named P again after C was published: P is live.
        family(
            "p-named-again",
            "c2",
            2 * HOUR,
            child(Some("p-named-again"), SIZE),
            Some(HOUR),
        );
        // C never used since its publication: not adopted.
        family(
            "p-unadopted",
            "c3",
            30 * HOUR,
            child(Some("p-unadopted"), SIZE),
            None,
        );
        // C not recorded (see below).
        family(
            "p-unrecorded",
            "c4",
            30 * HOUR,
            child(Some("p-unrecorded"), SIZE),
            Some(HOUR),
        );
        // A large orb created from a small snapshot: another size.
        family(
            "p-small",
            "c5",
            30 * HOUR,
            child(Some("p-small"), big),
            Some(HOUR),
        );
        // C's size not known (no size, no source orb).
        family(
            "p-unsized",
            "c6",
            30 * HOUR,
            serde_json::json!({"lineage": "new", "parent": "p-unsized"}),
            Some(HOUR),
        );
        // Published earlier than its "parent" (a republished key, or a cycle).
        snapshot(state, "p-later", image(), 20 * HOUR, Some(20 * HOUR));
        snapshot(
            state,
            "c7",
            child(Some("p-later"), SIZE),
            29 * HOUR,
            Some(HOUR),
        );
        // C is of a dead lineage, deleted in this same pass.
        snapshot(state, "p-dead-child", image(), 40 * HOUR, Some(30 * HOUR));
        snapshot(
            state,
            "c8",
            serde_json::json!({"lineage": "old", "parent": "p-dead-child", "size": SIZE}),
            29 * HOUR,
            Some(2 * HOUR),
        );
        // Its own parent.
        snapshot(
            state,
            "self",
            child(Some("self"), SIZE),
            29 * HOUR,
            Some(HOUR),
        );
        // P used 6 hours ago, before C: superseded, but not unused for long enough.
        snapshot(state, "p-recent", image(), 8 * HOUR, Some(6 * HOUR));
        snapshot(
            state,
            "c9",
            child(Some("p-recent"), SIZE),
            5 * HOUR,
            Some(HOUR),
        );

        let recorded = ["c", "c2", "c3", "c5", "c6", "c7", "c8", "c9", "self"];
        assert_eq!(
            doomed(state, Some(&["new"]), &recorded),
            of(&[("c8", Why::DeadLineage), ("p", Why::Superseded)])
        );
        assert_eq!(
            doomed(state, None, &recorded),
            of(&[("p", Why::Superseded), ("p-dead-child", Why::Superseded)]),
            "with lineages not known, nothing is dead: c8 supersedes its parent"
        );
    }

    /// Snapshots published before parents and sizes were recorded take them from their
    /// source orb's recipe (Firecracker or QEMU); a recorded parent, null for an image,
    /// wins. A QEMU orb built on a superseded snapshot keeps it.
    #[test]
    fn parents_and_sizes_come_from_the_source_orb_when_not_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let image = || child(None, SIZE);
        let fc = orb(state, 1, firecracker_recipe("projects/fc-parent"));
        snapshot(state, "fc-parent", image(), 40 * HOUR, Some(30 * HOUR));
        snapshot(
            state,
            "fc-child",
            serde_json::json!({"lineage": "new", "source_orb": fc}),
            29 * HOUR,
            Some(HOUR),
        );
        let other = orb(state, 2, firecracker_recipe("projects/not-a-parent"));
        snapshot(state, "not-a-parent", image(), 40 * HOUR, Some(30 * HOUR));
        snapshot(
            state,
            "recorded-image",
            serde_json::json!({"lineage": "new", "parent": null, "source_orb": other}),
            29 * HOUR,
            Some(HOUR),
        );
        let q = orb(state, 3, qemu_recipe(state, "projects/q-parent"));
        snapshot(state, "q-parent", image(), 40 * HOUR, Some(30 * HOUR));
        snapshot(
            state,
            "q-child",
            serde_json::json!({"lineage": "new", "source_orb": q}),
            29 * HOUR,
            Some(HOUR),
        );
        let meta = read_meta(state, &state.join("projects/q-child")).unwrap();
        assert_eq!(
            (meta.parent.as_deref(), meta.size),
            (Some("q-parent"), Some(SIZE))
        );
        let recorded = ["fc-child", "recorded-image", "q-child"];
        assert_eq!(
            doomed(state, Some(&["new"]), &recorded),
            of(&[("fc-parent", Why::Superseded)]),
            "q-parent is a QEMU orb's base"
        );
    }
}
