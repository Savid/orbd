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
//! snapshot goes sooner when it can no longer stand in for any image here (its lineage
//! is none of the current images', see [`DEAD_IDLE`]), or once another snapshot was
//! published here from an orb created from it (see [`SUPERSEDED_IDLE`]). Collection
//! runs at startup, hourly and after every orb delete, under
//! [`crate::runtime::vm::BASES`], so no disk is created from a base while it runs.

use super::{Shared, db};
use crate::runtime::vm::{self, BASES};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long an unused base is kept: Amp names a project snapshot for at most 72 hours.
pub const IDLE: Duration = Duration::from_secs(72 * 3600);
/// How long an unused project snapshot is kept once another one on this host was
/// published from an orb created from it: Amp names the newer one from then on. A parent
/// can have several (Amp keeps one per orb size, and on some repositories one per
/// member); one named again after it went costs that orb a start from its image.
pub const SUPERSEDED_IDLE: Duration = Duration::from_secs(12 * 3600);
/// How long an unused project snapshot is kept once its lineage is none of the lineages
/// the images here resolve to now: [`vm::initial_source`] passes it over for each of
/// them. The hour keeps one from going before the pause that published it has recorded
/// it (a publication counts as a use).
pub const DEAD_IDLE: Duration = Duration::from_secs(3600);
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
    let found = {
        let (state, images) = (state.clone(), sh.images.clone());
        tokio::task::spawn_blocking(move || {
            let in_use = orb_bases(&state)?;
            let lineages = images
                .as_ref()
                .map(|s| s.current_lineages())
                .unwrap_or_default();
            let projects = collect_projects(&state, &in_use, &lineages);
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
            Ok::<_, String>((projects, images))
        })
        .await
    };
    let (projects, images) = match found {
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
    // Forgotten before a snapshot of the same key can be published again.
    for p in &projects {
        let key = p.key.clone();
        if let Err(e) = sh
            .db
            .call(move |c| db::forget_project_snapshot(c, &key))
            .await
        {
            tracing::warn!(error = %e, "forgetting a deleted project snapshot");
        }
    }
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
             superseded and unused for {}h, or of a lineage no current image has and \
             unused for {}h",
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
    /// Of a lineage no current image has, and unused for [`DEAD_IDLE`].
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

/// A project snapshot moved into the trash.
#[derive(Debug)]
struct Trashed {
    key: String,
    trashed: PathBuf,
    why: Why,
}

/// What a project snapshot's `meta.json` says it descends from: its image lineage and
/// its parent (the snapshot its source orb's disk was created from; None: an image, or
/// not known). Snapshots published before parents were recorded take the parent from
/// their source orb's recipe while that orb is here.
fn descent(state: &Path, dir: &Path) -> (Option<String>, Option<String>) {
    let Some(meta) = std::fs::read(dir.join("meta.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
    else {
        return (None, None);
    };
    let lineage = meta
        .get("lineage")
        .and_then(|l| l.as_str())
        .map(str::to_owned);
    let parent = match meta.get("parent") {
        Some(p) => p.as_str().map(str::to_owned),
        None => meta
            .get("source_orb")
            .and_then(|o| o.as_str())
            .filter(|o| crate::model::OrbId::parse(o).is_ok())
            .and_then(|o| std::fs::read(state.join("orbs").join(o).join("vm.json")).ok())
            .and_then(|json| {
                crate::runtime::qemu::recipe_project(&json)
                    .or_else(|| crate::runtime::firecracker::recipe_project(&json))
            })
            .flatten(),
    };
    (lineage, parent)
}

/// Moves into the trash every project snapshot not in `in_use` that is unused for
/// [`IDLE`], superseded and unused for [`SUPERSEDED_IDLE`], or (with `lineages`, the
/// current images' lineages, known) of none of `lineages` and unused for [`DEAD_IDLE`].
fn collect_projects(
    state: &Path,
    in_use: &HashSet<String>,
    lineages: &HashSet<String>,
) -> Vec<Trashed> {
    struct Found {
        key: String,
        path: PathBuf,
        dead: bool,
        parent: Option<String>,
    }
    let dir = state.join("projects");
    let found: Vec<Found> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| {
            let path = e.path();
            let (lineage, parent) = descent(state, &path);
            Found {
                key: e.file_name().to_string_lossy().into_owned(),
                // As `initial_source` decides: a snapshot without a lineage is passed over
                // too, once the image's is known.
                dead: !lineages.is_empty() && lineage.is_none_or(|l| !lineages.contains(&l)),
                parent,
                path,
            }
        })
        .collect();
    // Only a snapshot that can still be used supersedes its parent.
    let superseded: HashSet<&str> = found
        .iter()
        .filter(|f| !f.dead)
        .filter_map(|f| f.parent.as_deref().filter(|p| *p != f.key))
        .collect();
    let mut deleted = Vec::new();
    for f in &found {
        if in_use.contains(&format!("projects/{}", f.key)) {
            continue;
        }
        let unused = match vm::last_used(&f.path) {
            Ok(t) => t.elapsed().unwrap_or_default(),
            Err(e) => {
                let key = &f.key;
                tracing::warn!(key, error = %e, "garbage collection: no use time; keeping it");
                continue;
            }
        };
        let why = if unused >= IDLE {
            Why::Idle
        } else if f.dead && unused >= DEAD_IDLE {
            Why::DeadLineage
        } else if superseded.contains(f.key.as_str()) && unused >= SUPERSEDED_IDLE {
            Why::Superseded
        } else {
            continue;
        };
        match vm::fsutil::move_to_trash(&f.path, &state.join("trash")) {
            Ok(Some(t)) => deleted.push(Trashed {
                key: f.key.clone(),
                trashed: t,
                why,
            }),
            Ok(None) => {}
            Err(e) => {
                let key = &f.key;
                tracing::warn!(key, error = %e, "deleting an unused project snapshot");
            }
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn age(path: &Path, days: u64) {
        ago(path, Duration::from_secs(days * 86_400));
    }

    fn ago(path: &Path, by: Duration) {
        let t = SystemTime::now() - by;
        std::fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    const HOUR: Duration = Duration::from_secs(3600);

    /// A published project snapshot `key` with `meta` as its `meta.json`, last used
    /// `unused` ago.
    fn snapshot(state: &Path, key: &str, meta: serde_json::Value, unused: Duration) {
        let dir = state.join("projects").join(key);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("meta.json"), meta.to_string()).unwrap();
        ago(&dir, unused);
    }

    /// An orb directory `n` with `recipe` as its `vm.json`; returns the orb id.
    fn orb(state: &Path, n: u8, recipe: String) -> String {
        let id = format!("01a17b00-0000-7000-8000-0000000000{n:02}");
        let dir = state.join("orbs").join(&id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vm.json"), recipe).unwrap();
        id
    }

    fn keys(trashed: &[Trashed], why: Why) -> Vec<&str> {
        let mut k: Vec<&str> = trashed
            .iter()
            .filter(|t| t.why == why)
            .map(|t| t.key.as_str())
            .collect();
        k.sort();
        k
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
    /// once idle, like one no orb was ever built on.
    #[test]
    fn firecracker_orbs_pin_no_base() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        for (i, base) in ["projects/copied", "images/k1"].iter().enumerate() {
            let dir = state
                .join("orbs")
                .join(format!("01a17b00-0000-7000-8000-00000000000{i}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("vm.json"), firecracker_recipe(base)).unwrap();
        }
        std::fs::create_dir_all(state.join("projects/copied")).unwrap();
        age(&state.join("projects/copied"), 4);

        let in_use = orb_bases(state).unwrap();
        assert!(in_use.is_empty(), "{in_use:?}");
        let trashed = collect_projects(state, &in_use, &HashSet::new());
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].key, "copied");
    }

    /// Only a project snapshot that no orb is built on and nothing used for the idle
    /// time is deleted; an orb recipe that cannot be read stops all deletion.
    #[test]
    fn deletes_only_unused_idle_project_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        for (i, base) in ["projects/built-on", "images/k1"].iter().enumerate() {
            let dir = state
                .join("orbs")
                .join(format!("01a17b00-0000-7000-8000-00000000000{i}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("vm.json"), qemu_recipe(state, base)).unwrap();
        }
        for key in ["built-on", "idle", "fresh", "used-lately"] {
            std::fs::create_dir_all(state.join("projects").join(key)).unwrap();
        }
        vm::mark_used(&state.join("projects/used-lately"));
        for key in ["built-on", "idle", "used-lately"] {
            age(&state.join("projects").join(key), 4);
        }

        let in_use = orb_bases(state).unwrap();
        assert_eq!(
            in_use,
            HashSet::from(["projects/built-on".to_owned(), "images/k1".to_owned()])
        );
        let trashed = collect_projects(state, &in_use, &HashSet::new());
        assert_eq!(trashed.len(), 1);
        assert_eq!(trashed[0].key, "idle");
        let mut left: Vec<String> = std::fs::read_dir(state.join("projects"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["built-on", "fresh", "used-lately"]);

        let broken = state.join("orbs/01a17b00-0000-7000-8000-000000000009");
        std::fs::create_dir_all(&broken).unwrap();
        assert!(
            orb_bases(state).is_err(),
            "an orb directory without vm.json"
        );
        std::fs::write(broken.join("vm.json"), b"{").unwrap();
        assert!(orb_bases(state).is_err(), "an unreadable vm.json");
    }

    /// With the current images' lineages known, a snapshot of none of them (or of no
    /// recorded lineage) goes once unused for an hour, unless a QEMU orb is built on it;
    /// with none known, only idle ones go.
    #[test]
    fn dead_lineage_snapshots_go_after_an_hour() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        orb(state, 1, qemu_recipe(state, "projects/old-built-on"));
        let old = serde_json::json!({"lineage": "old", "parent": null});
        snapshot(state, "old-built-on", old.clone(), 2 * HOUR);
        snapshot(state, "old-unused", old.clone(), 2 * HOUR);
        snapshot(state, "old-just-published", old, Duration::from_secs(600));
        snapshot(state, "unrecorded", serde_json::json!({}), 2 * HOUR);
        snapshot(
            state,
            "current",
            serde_json::json!({"lineage": "new"}),
            2 * HOUR,
        );
        let in_use = orb_bases(state).unwrap();

        assert!(
            collect_projects(state, &in_use, &HashSet::new()).is_empty(),
            "no current lineage known: nothing is dead"
        );
        let trashed = collect_projects(state, &in_use, &HashSet::from(["new".to_owned()]));
        assert_eq!(
            keys(&trashed, Why::DeadLineage),
            ["old-unused", "unrecorded"]
        );
        assert_eq!(trashed.len(), 2);
        let other = HashSet::from(["new".to_owned(), "old".to_owned()]);
        assert!(
            collect_projects(state, &in_use, &other).is_empty(),
            "a lineage one current image has is alive"
        );
    }

    /// A snapshot another one here was published from (its parent, recorded or taken
    /// from the source orb's recipe) goes once unused for 12 hours; one a dead or no
    /// snapshot descends from waits for the idle time.
    #[test]
    fn superseded_snapshots_go_after_twelve_hours() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let meta = |parent: Option<&str>| serde_json::json!({"lineage": "new", "parent": parent});
        snapshot(state, "parent", meta(None), 13 * HOUR);
        snapshot(state, "child", meta(Some("parent")), 13 * HOUR);
        snapshot(state, "recent-parent", meta(None), 6 * HOUR);
        snapshot(state, "recent-child", meta(Some("recent-parent")), HOUR);
        snapshot(state, "orphan", meta(Some("long-gone")), 13 * HOUR);
        snapshot(state, "own-parent", meta(Some("own-parent")), 13 * HOUR);
        // Its only child is of a dead lineage (and goes itself).
        snapshot(state, "dead-childs-parent", meta(None), 13 * HOUR);
        snapshot(
            state,
            "dead-child",
            serde_json::json!({"lineage": "old", "parent": "dead-childs-parent"}),
            13 * HOUR,
        );
        // Published before parents were recorded: the source orb's recipe says.
        let source = orb(state, 2, firecracker_recipe("projects/legacy-parent"));
        snapshot(state, "legacy-parent", meta(None), 13 * HOUR);
        snapshot(
            state,
            "legacy-child",
            serde_json::json!({"lineage": "new", "source_orb": source}),
            HOUR,
        );
        // A recorded parent wins over the recipe: null is an image.
        let other = orb(state, 3, firecracker_recipe("projects/not-a-parent"));
        snapshot(state, "not-a-parent", meta(None), 13 * HOUR);
        snapshot(
            state,
            "recorded-image",
            serde_json::json!({"lineage": "new", "parent": null, "source_orb": other}),
            HOUR,
        );
        let in_use = orb_bases(state).unwrap();
        let lineages = HashSet::from(["new".to_owned()]);

        let trashed = collect_projects(state, &in_use, &lineages);
        assert_eq!(keys(&trashed, Why::Superseded), ["legacy-parent", "parent"]);
        assert_eq!(keys(&trashed, Why::DeadLineage), ["dead-child"]);
        assert_eq!(trashed.len(), 3);
        let mut left: Vec<String> = std::fs::read_dir(state.join("projects"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            [
                "child",
                "dead-childs-parent",
                "legacy-child",
                "not-a-parent",
                "orphan",
                "own-parent",
                "recent-child",
                "recent-parent",
                "recorded-image"
            ]
        );
    }

    /// A QEMU orb built on a superseded snapshot keeps it; its recipe names the parent
    /// of a snapshot published from it.
    #[test]
    fn qemu_orbs_keep_superseded_bases_and_name_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let source = orb(state, 1, qemu_recipe(state, "projects/q-parent"));
        snapshot(
            state,
            "q-parent",
            serde_json::json!({"lineage": "new"}),
            13 * HOUR,
        );
        snapshot(
            state,
            "q-child",
            serde_json::json!({"lineage": "new", "source_orb": source}),
            HOUR,
        );
        assert_eq!(
            descent(state, &state.join("projects/q-child")),
            (Some("new".to_owned()), Some("q-parent".to_owned()))
        );
        let in_use = orb_bases(state).unwrap();
        let trashed = collect_projects(state, &in_use, &HashSet::from(["new".to_owned()]));
        assert!(trashed.is_empty(), "{trashed:?}");
    }
}
