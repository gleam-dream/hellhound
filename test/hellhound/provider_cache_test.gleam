//// The provider cache keeps serving its last good snapshot while a key
//// refresh or reload is slow.

import gleam/erlang/process
import gleam/erlang/reference
import gleam/list
import hellhound/internal/native/provider
import hellhound/internal/secure
import hellhound/internal/transport
import hellhound/testing
import hellhound_test_support as support

@external(erlang, "hellhound_fetch_ownership_test", "slow_key_refresh_does_not_block_cached_snapshots")
pub fn slow_key_refresh_does_not_block_cached_snapshots_test() -> Nil

/// Test fixture construction stays typed; lifecycle tests observe the actor
/// through its existing handle rather than unpacking its private state.
fn lifecycle_policy(fixture: testing.Provider) -> transport.Policy {
  transport.Policy(
    ..transport.policy(transport.Anchors([testing.trust_anchor_der(fixture)])),
    allow_loopback: True,
    timeout_ms: 5000,
  )
}

pub fn start_for_lifecycle(
  fixture: testing.Provider,
) -> #(process.Pid, provider.Provider) {
  let name = process.new_name("provider_cache_lifecycle")
  let assert Ok(started) =
    provider.start(
      name,
      testing.issuer(fixture),
      lifecycle_policy(fixture),
      fn(_) { True },
      secure.monotonic_ms,
    )
  #(started.pid, provider.Provider(started.data, 5000))
}

/// A probe that outlives its lease is replaced. Its late report must not
/// close the circuit, or release it, while the probe that replaced it is
/// still in flight.
pub fn a_replaced_probe_does_not_decide_the_circuit_test() {
  let assert Ok(fixture) = testing.start_provider(testing.provider_options())
  let clock = support.clock_new(0)
  let name = process.new_name("provider_cache_circuit")
  let assert Ok(started) =
    provider.start(
      name,
      testing.issuer(fixture),
      lifecycle_policy(fixture),
      fn(_) { True },
      fn() { support.clock_read(clock) },
    )
  let cache = provider.Provider(started.data, 5000)
  let lease = 1000
  let assert provider.Admitted(..) as admitted =
    provider.admit_renewal(cache, lease)
  provider.renewal_reported(cache, admitted, provider.Faulted)
  assert provider.admit_renewal(cache, lease) == provider.Paused
  // The window ends: the first probe. It does not report within its lease.
  support.clock_set(clock, 60_000)
  let assert provider.Probe(..) as first = provider.admit_renewal(cache, lease)
  assert provider.admit_renewal(cache, lease) == provider.Paused
  support.clock_set(clock, 61_000)
  let assert provider.Probe(..) as second = provider.admit_renewal(cache, lease)
  assert second != first
  // The replaced probe reports late, either way: nothing changes.
  provider.renewal_reported(cache, first, provider.Answered)
  assert provider.admit_renewal(cache, lease) == provider.Paused
  provider.renewal_reported(cache, first, provider.NothingLearned)
  assert provider.admit_renewal(cache, lease) == provider.Paused
  // The probe that holds the circuit closes it.
  provider.renewal_reported(cache, second, provider.Answered)
  let assert provider.Admitted(..) = provider.admit_renewal(cache, lease)
  process.unlink(started.pid)
  process.kill(started.pid)
  testing.stop_provider(fixture)
}

/// A report reaches the cache's name, which outlives a restart. A renewal
/// admitted by an earlier incarnation must not open, close or release the
/// circuit of the one that replaced it.
pub fn a_report_from_an_earlier_incarnation_changes_nothing_test() {
  let assert Ok(fixture) = testing.start_provider(testing.provider_options())
  let clock = support.clock_new(0)
  let start = fn(name) {
    let assert Ok(started) =
      provider.start(
        process.new_name(name),
        testing.issuer(fixture),
        lifecycle_policy(fixture),
        fn(_) { True },
        fn() { support.clock_read(clock) },
      )
    #(started.pid, provider.Provider(started.data, 5000))
  }
  let lease = 1000
  let #(earlier_pid, earlier) = start("provider_cache_earlier")
  let #(current_pid, current) = start("provider_cache_current")
  let assert provider.Admitted(..) as stale =
    provider.admit_renewal(earlier, lease)
  // A fault from the earlier incarnation does not open the current circuit.
  provider.renewal_reported(current, stale, provider.Faulted)
  let assert provider.Admitted(..) as admitted =
    provider.admit_renewal(current, lease)
  // The current circuit opens and probes; the earlier incarnation's answer
  // does not close it.
  provider.renewal_reported(current, admitted, provider.Faulted)
  // Reports are asynchronous; this call is answered after the fault.
  assert provider.admit_renewal(current, lease) == provider.Paused
  support.clock_set(clock, 60_000)
  let assert provider.Probe(..) = provider.admit_renewal(current, lease)
  provider.renewal_reported(current, stale, provider.Answered)
  assert provider.admit_renewal(current, lease) == provider.Paused
  // A renewal admitted by no running cache reaches no circuit either.
  provider.renewal_reported(
    current,
    provider.Admitted(reference.new()),
    provider.Answered,
  )
  assert provider.admit_renewal(current, lease) == provider.Paused
  list.each([earlier_pid, current_pid], fn(pid) {
    process.unlink(pid)
    process.kill(pid)
  })
  testing.stop_provider(fixture)
}
