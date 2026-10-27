# hellhound reference consumer

[![CI](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml)
[![hellhound on Hex](https://img.shields.io/hexpm/v/hellhound?label=Hex%3A%20hellhound)](https://hex.pm/packages/hellhound)
[![Gleam](https://img.shields.io/badge/Gleam-FFAFF3?logo=gleam&logoColor=000000)](https://gleam.run/)

A separate relying-party application testing Hellhound's public API against a
local test provider. It supplies browser routes, application session storage, route
protection, and one runnable example per topic.

| Topic                                             | Example                                                  |
| ------------------------------------------------- | -------------------------------------------------------- |
| Sign in, call an API, sign out                    | `src/hellhound_reference/usage/login.gleam`              |
| Run under a supervisor                            | `src/hellhound_reference/usage/supervision.gleam`        |
| Durable sessions, conditional writes, nodes       | `src/hellhound_reference/usage/durable_store.gleam`      |
| Several callback addresses                        | `src/hellhound_reference/usage/callback_addresses.gleam` |
| Resource-server validation and introspection      | `src/hellhound_reference/usage/resource_server.gleam`    |
| Local test provider                               | `src/hellhound_reference/usage/test_provider.gleam`      |
| Application decisions around Hellhound's evidence | `src/hellhound_reference/usage/responsibilities.gleam`   |

`test/usage_test.gleam` runs every example. Root README snippets are reviewed
manually for consistency. `src/hellhound_reference/web.gleam` holds browser routes and
`protect.gleam` the route protection; `test/hellhound_reference_test.gleam` runs the
common login path and `browser/` holds the browser reproduction.

```sh
cd consumer && gleam test
```

The design's "Application responsibilities" section states the decisions this
application makes.
