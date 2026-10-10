// expect: WriteOutcome
import gleam/option.{None}
import warden/store

pub fn main() -> store.Store {
  store.new(
    get: fn(_) { Ok(None) },
    put: fn(_, _) { Ok(True) },
    delete_expired: fn(_) { Ok(0) },
  )
}
