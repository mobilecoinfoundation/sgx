# MobileCoin SGX: Trusted Services test utilities

Utilities to assist with testing the `libsgx_tservice` rust interface.

This crate is not meant to be published and should only be used locally.

When using this crate as a development dependency be sure and avoid calling out
the `version`. Using the version attribute will cause an error when
running `cargo package`.

```yaml
[dev-dependencies]
  test_utils = { path = "<path>/<to>/test_utils" } #<-- no version
```
