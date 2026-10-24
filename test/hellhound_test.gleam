//// Test entry point. See `hellhound_test_runner.erl` for suite selection.

pub fn main() -> Nil {
  run()
}

@external(erlang, "hellhound_test_runner", "main")
fn run() -> Nil
