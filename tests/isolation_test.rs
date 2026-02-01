use std::cell::RefCell;
use std::ffi::OsString;

use rsdebstrap::executor::{CommandExecutor, CommandSpec, ExecutionResult};
use rsdebstrap::isolation::{ChrootIsolation, Isolation};

#[derive(Default)]
struct RecordingExecutor {
    calls: RefCell<Vec<(String, Vec<OsString>)>>,
}

impl CommandExecutor for RecordingExecutor {
    fn execute(&self, spec: &CommandSpec) -> anyhow::Result<ExecutionResult> {
        self.calls
            .borrow_mut()
            .push((spec.command.clone(), spec.args.clone()));
        Ok(ExecutionResult { status: None })
    }
}

#[test]
fn test_chroot_isolation_name() {
    let isolation = ChrootIsolation;
    assert_eq!(isolation.name(), "chroot");
}

#[test]
fn test_chroot_isolation_execute_builds_correct_args() {
    let isolation = ChrootIsolation;
    let executor = RecordingExecutor::default();
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<OsString> = vec!["/bin/sh".into(), "/tmp/script.sh".into()];

    let result = isolation.execute(rootfs, &command, &executor);
    assert!(result.is_ok());

    let calls = executor.calls.borrow();
    assert_eq!(calls.len(), 1);
    let (cmd, args) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args.len(), 3);
    assert_eq!(args[0], "/tmp/rootfs");
    assert_eq!(args[1], "/bin/sh");
    assert_eq!(args[2], "/tmp/script.sh");
}

#[test]
fn test_chroot_isolation_execute_empty_command() {
    let isolation = ChrootIsolation;
    let executor = RecordingExecutor::default();
    let rootfs = camino::Utf8Path::new("/tmp/rootfs");
    let command: Vec<OsString> = vec![];

    let result = isolation.execute(rootfs, &command, &executor);
    assert!(result.is_ok());

    let calls = executor.calls.borrow();
    assert_eq!(calls.len(), 1);
    let (cmd, args) = &calls[0];
    assert_eq!(cmd, "chroot");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0], "/tmp/rootfs");
}
