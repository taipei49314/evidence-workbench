use anyhow::{Result, bail};
use serde_json::Value;

pub fn current() -> Result<Value> {
    bail!("build identity is unavailable in the package-excluded test harness")
}
