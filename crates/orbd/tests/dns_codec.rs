//! `orbd dns-codec`, the restricted-egress DNS proxy's codec, as the binary runs it
//! (unjailed here; the agent jails it, see the restricted-egress gate in `kvm.rs`): it
//! serves decode and encode requests on its socket under its own seccomp filter and
//! `no_new_privs`, and exits when the socket closes.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

fn query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

fn send(s: &mut UnixStream, msg: &[u8]) -> Vec<u8> {
    s.write_all(&(msg.len() as u32).to_be_bytes()).unwrap();
    s.write_all(msg).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap();
    let mut out = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut out).unwrap();
    out
}

fn status(pid: u32, field: &str) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(field).map(|v| v.trim().to_owned()))
        .unwrap_or_default()
}

#[test]
fn the_codec_serves_its_socket_under_its_filter() {
    let (mut agent, codec) = UnixStream::pair().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_orbd"))
        .arg("dns-codec")
        .env_clear()
        .stdin(Stdio::from(std::os::fd::OwnedFd::from(codec)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    agent
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let q = query(0x1234, "WWW.Example.com");
    // Decode: a question with the normalized name.
    let mut decode = vec![1, 0, 0, 0, 7];
    decode.extend_from_slice(&q);
    let r = send(&mut agent, &decode);
    let name = b"www.example.com";
    let mut want = vec![1, 0, 0, 0, 7, 0, 0, 1, 0, 1, name.len() as u8];
    want.extend_from_slice(name);
    assert_eq!(r, want);
    assert_eq!(status(child.id(), "Seccomp:"), "2");
    assert_eq!(status(child.id(), "NoNewPrivs:"), "1");
    // Encode: NXDOMAIN, no records, to the query's id.
    let mut encode = vec![2, 0, 0, 0, 8, 1, 3, 0, 0];
    encode.extend_from_slice(&q);
    let r = send(&mut agent, &encode);
    assert_eq!(&r[..5], &[2, 0, 0, 0, 8]);
    assert_eq!(&r[5..7], &[0x12, 0x34], "the query's id");
    assert_eq!(r[8] & 0x0f, 3, "NXDOMAIN");
    // Many more, as a busy agent sends them.
    for i in 0..500u32 {
        let mut d = vec![1];
        d.extend_from_slice(&i.to_be_bytes());
        d.extend_from_slice(&query(i as u16, &format!("n{i}.example")));
        assert_eq!(send(&mut agent, &d)[0], 1);
    }
    drop(agent);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{:?}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_codec_runs_only_on_its_socket() {
    let out = Command::new(env!("CARGO_BIN_EXE_orbd"))
        .arg("dns-codec")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

/// The codec as the agent starts it, as root (skipped otherwise unless `ORBD_TEST_JAIL=1`
/// requires it): jailed as the uid above every orb's, with no capabilities, its own
/// network namespace and nothing but itself in its root, it answers through the agent's
/// client.
#[test]
fn the_agent_starts_the_codec_jailed() {
    if !nix::unistd::geteuid().is_root() {
        assert!(
            std::env::var("ORBD_TEST_JAIL").is_err(),
            "ORBD_TEST_JAIL is set but the test does not run as root"
        );
        eprintln!("skipped: needs root");
        return;
    }
    use orbd::runtime::vm::codec;
    let dir = tempfile::tempdir().unwrap();
    let (state, run) = (dir.path().join("state"), dir.path().join("run"));
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    let base = 1_300_400_000;
    let jailer = orbd::runtime::vm::jail::Jailer::new(
        orbd::config::agent::VmmJail { uid_base: base },
        &state,
        &run,
    )
    .unwrap();
    let bin = std::path::PathBuf::from(env!("CARGO_BIN_EXE_orbd"));
    let jail = jailer.codec_jail(&bin).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let c = codec::start(codec::process_spawner(Some(jail))(), "test")
            .await
            .unwrap();
        let q = query(7, "a.example");
        match c.decode(&q).await {
            Some(codec::Decoded::Question(q)) => assert_eq!(q.name.as_deref(), Some("a.example")),
            other => panic!("{other:?}"),
        }
        let me = std::process::id();
        let id = (base + (1 << 24) + 1).to_string();
        // The codecs this test started: its children with `dns-codec` as their uid.
        let codecs = || -> Vec<u32> {
            std::fs::read_dir("/proc")
                .unwrap()
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
                .filter(|p| {
                    let stat =
                        std::fs::read_to_string(format!("/proc/{p}/stat")).unwrap_or_default();
                    let (ppid, state) = stat
                        .rsplit_once(')')
                        .map(|(_, r)| {
                            let mut f = r.split_whitespace();
                            let state = f.next().unwrap_or("").to_owned();
                            (f.next().and_then(|p| p.parse::<u32>().ok()), state)
                        })
                        .unwrap_or_default();
                    ppid == Some(me)
                        && state != "Z"
                        && status(*p, "Uid:").split_whitespace().next() == Some(id.as_str())
                })
                .collect()
        };
        let found = codecs();
        assert_eq!(found.len(), 1, "{found:?}");
        let pid = found[0];
        assert_eq!(
            status(pid, "Uid:").split_whitespace().collect::<Vec<_>>(),
            [id.as_str(); 4]
        );
        assert_eq!(status(pid, "CapEff:"), "0000000000000000");
        assert_eq!(status(pid, "CapBnd:"), "0000000000000000");
        assert_eq!(status(pid, "NoNewPrivs:"), "1");
        assert_eq!(status(pid, "Seccomp:"), "2");
        // Its namespaces and root need CAP_SYS_PTRACE to inspect (the KVM gates have it).
        let ns = |p: u32| std::fs::read_link(format!("/proc/{p}/ns/net"));
        match ns(pid) {
            Ok(theirs) => {
                assert_ne!(theirs, ns(me).unwrap(), "a network namespace of its own");
                let root = std::path::PathBuf::from(format!("/proc/{pid}/root"));
                for hidden in ["proc/self", "etc/passwd", "tmp"] {
                    assert!(!root.join(hidden).exists(), "the codec sees /{hidden}");
                }
                assert!(!root.join(state.strip_prefix("/").unwrap()).exists());
                assert!(root.join("orbd").exists(), "its binary");
                assert!(!root.join(bin.strip_prefix("/").unwrap()).exists());
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("NOTICE: no CAP_SYS_PTRACE: the codec's namespaces are not checked")
            }
            Err(e) => panic!("{e}"),
        }
        // Killed, it is started again and answers; stopped, it is gone for good.
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(pid as i32),
            nix::sys::signal::Signal::SIGKILL,
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let now = codecs();
            if now.len() == 1 && now[0] != pid {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "not started again: {now:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let q = query(8, "b.example");
        assert!(matches!(
            c.decode(&q).await,
            Some(codec::Decoded::Question(_))
        ));
        c.stop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !codecs().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "still running after stop"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    });
}
