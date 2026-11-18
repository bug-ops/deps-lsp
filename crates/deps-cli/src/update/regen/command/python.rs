//! Invocation shapes of the Python lockers.

use std::path::Path;

use super::{ArgComponent, Invocation, NonEmpty, Program};

impl Invocation {
    /// `uv lock --no-build --no-python-downloads` with one `--upgrade-package <name>==<version>`
    /// per pin: no sdist build, no interpreter download, exact versions only.
    pub(in crate::update::regen) fn uv_lock(
        cwd: &Path,
        pins: &NonEmpty<(ArgComponent, ArgComponent)>,
    ) -> Self {
        let mut args = Self::strs(&["lock", "--no-build", "--no-python-downloads"]);
        for (name, version) in pins.iter() {
            args.push("--upgrade-package".into());
            args.push(format!("{}=={}", name.as_str(), version.as_str()).into());
        }
        Self::new(Program::Uv, cwd, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uv_lock_emits_one_upgrade_flag_per_pin() {
        let pin = |n: &str, v: &str| {
            (
                ArgComponent::parse(n).expect("name"),
                ArgComponent::parse(v).expect("version"),
            )
        };
        let pins = NonEmpty::new(vec![pin("a", "1.0.0"), pin("b", "2.0.0")]).expect("non-empty");
        let invocation = Invocation::uv_lock(Path::new("."), &pins);
        let args: Vec<_> = invocation
            .args()
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(
            args,
            [
                "lock",
                "--no-build",
                "--no-python-downloads",
                "--upgrade-package",
                "a==1.0.0",
                "--upgrade-package",
                "b==2.0.0"
            ]
        );
    }
}
