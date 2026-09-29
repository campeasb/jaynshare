//! Client installers. The macOS halves run here; the Windows halves skip
//! off Windows. The OS trust store is reached through the fake
//! `security`/`certutil` (`fake_tools::FakeTools`), the Windows ACL through
//! the fake `icacls`.

#[allow(unused_imports)]
use crate::bundle::{Operator, config_root};
#[allow(unused_imports)]
use crate::fake_tools::FakeTools;
#[allow(unused_imports)]
use crate::harness::{cli_pty, cli_raw, isolated_env, scratch};
