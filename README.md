# MobileCoin SGX

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->[![Dependency Status][deps-image]][deps-link]<!--
-->[![CodeCov Status][codecov-image]][codecov-link]<!--
-->[![GitHub Workflow Status][gha-image]][gha-link]

A collection of crates which wrap Intel's [SGX SDK][sgx] and [Data Center Attestation Primitives][dcap] suites.

## Releasing

The crates are released as one workspace.  This means a release is due to one
crate, *all* of the crates will be released with a new version, even if there
is no change to the others.

The suggested method for releasing of these crates is with
[cargo release](https://github.com/crate-ci/cargo-release).

The following command will do a dry run showing a user what would happen

```shell
cargo release
```

To see the commits that will be created one could do

```shell
cargo release --no-publish --no-push --no-tag --no-confirm --workspace --dev-version --execute
```

This will create 2 commits similar to

```shell
commit 0bba4ae48d726080ac0e34e65bab6efa3583519d 
Author: Joe Schmoe <joe@schmoe.com>
Date:   Tue Oct 4 13:30:21 2018 -0700

    (cargo-release) start next development iteration 0.2.1-pre

commit 89ac834220465cdff691b590bcf21bab66b3c08d
Author: Joe Schmoe <joe@schmoe.com>
Date:   Tue Oct 4 13:30:20 2018 -0700

    (cargo-release) version 0.2.0
```

The first (bottom most) commit will be updating to the next by removing the
development suffix `-pre`.  The second (topmost) will bump the patch version
and add back the development suffix.

[sgx]: https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/linux-overview.html
[dcap]: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/
[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[license-image]: https://img.shields.io/crates/l/mc-sgx-tservice-sys-types?style=flat-square
[deps-image]: https://deps.rs/repo/github/mobilecoinfoundation/sgx/status.svg?style=flat-square
[deps-link]: https://deps.rs/repo/github/mobilecoinfoundation/sgx
[codecov-image]: https://img.shields.io/codecov/c/github/mobilecoinfoundation/sgx/develop?style=flat-square
[codecov-link]: https://codecov.io/gh/mobilecoinfoundation/sgx
[gha-image]: https://img.shields.io/github/workflow/status/mobilecoinfoundation/sgx/rust/main?style=flat-square
[gha-link]: https://github.com/mobilecoinfoundation/sgx/actions/workflows/build.yaml?query=branch%3Amain
