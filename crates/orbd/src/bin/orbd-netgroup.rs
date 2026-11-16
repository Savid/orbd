//! `orbd-netgroup PROGRAM [ARGS...]` runs PROGRAM with this binary's group. Installed
//! setgid to `runtime.qemu.network_group`, it starts QEMU so that QEMU's sockets carry
//! that group and the host firewall confines them. The group grants nothing: it only
//! gets firewalled, so this can exec anything.

use std::os::unix::process::CommandExt;
use std::process::{Command, exit};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(program) = args.next() else {
        eprintln!("usage: orbd-netgroup PROGRAM [ARGS...]");
        exit(2);
    };
    let err = Command::new(&program).args(args).exec();
    eprintln!("orbd-netgroup: {}: {err}", program.to_string_lossy());
    exit(127);
}
