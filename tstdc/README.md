# MobileCoin: Rust wrappers around SGX synchronization primitives

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Target][target-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

Rust wrappers around SGX synchronization primitives.

The primitives exposed through this crate are low-level building blocks for
higher-level constructs. Most people will want to use
[mc-sgx-sync](https://docs.rs/mc-sgx-sync/latest/mc_sgx_sync/) to get
[std::sync](https://doc.rust-lang.org/std/sync/) compatible constructs.

The underlying implementation of [`Mutex`], [`RwLock`], and [`Condvar`] make
OCALLs:

- `sgx_thread_wait_untrusted_event_ocall()`
- `sgx_thread_set_multiple_untrusted_events_ocall()`
- `sgx_thread_set_untrusted_event_ocall()`
- `sgx_thread_setwait_untrusted_events_ocall()`

These OCALLs are provided the waiting thread(s) and a return value to fill out.
The OCALLs can suspend and or spuriously wake up trusted threads. The
application (untrusted) inherently has control of whether the enclave thread(s)
will execute. The OCALLs further increase the surface area that the application
has in controlling the execution of enclave thread(s). Using these
synchronization primitives, the application is now capable of stopping enclave
thread(s) consistently at the synchronization points.

[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[license-image]: https://img.shields.io/crates/l/mc-sgx-tstdc?style=flat-square
[target-image]: https://img.shields.io/badge/target-sgx-red?style=flat-square
[crate-image]: https://img.shields.io/crates/v/mc-sgx-tstdc.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-sgx-tstdc
[docs-image]: https://img.shields.io/docsrs/mc-sgx-tstdc?style=flat-square
[docs-link]: https://docs.rs/crate/mc-sgx-tstdc
[deps-image]: https://deps.rs/crate/mc-sgx-tstdc/0.1.0/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-sgx-tstdc/0.1.0
