# web5-sdk-kotlin

[![License](https://img.shields.io/npm/l/@tbd54566975/web5-kt.svg?style=flat-square&color=24f2ff&logo=apache&logoColor=FFFFFF&santize=true)](https://github.com/TBD54566975/web5-kt/blob/main/LICENSE)
 [![SDK Kotlin CI](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml/badge.svg)](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/codecov/c/gh/tbd54566975/web5-kt/main?logo=codecov&logoColor=FFFFFF&style=flat-square&token=YI87CKF1LI)](https://codecov.io/github/TBD54566975/web5-kt)


This repo contains 4 jvm packages:

* [common](./common) - utilities for encoding, decoding, and hashing
* [crypto](./crypto) - key generation, signing, signature verification, encryption, and decryption
* [dids](./dids) - did generation and resolution
* [credentials](./credentials) - creation and verification of verifiable claims

# Quickstart

All the web5 libraries are published on [JitPack](https://jitpack.io). To start simply add the following to your
`gradle.build.kts` file:

```kotlin
repositories {
  maven(url = "https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  implementation("com.github.TBD54566975:web5-sdk-kotlin:master-SNAPSHOT")
}
```

NOTE: The repository at `https://repo.danubetech.com/repository/maven-public/` is required for resolving transitive
dependencies.

If you want to refer to a specific release, then replace the `master-SNAPSHOT` with release tag.

If you want to pull a PR, then replace `master-SNAPSHOT` using the template `PR<NR>-SNAPSHOT`. For
example `PR40-SNAPSHOT`.

If you want to depend on a single module, like `credentials`, then use the following dependencies

```kotlin
dependencies {
  implementation("com.github.TBD54566975.web5-sdk-kotlin:credentials:master-SNAPSHOT")
}
```

# Building

To build and run test just run:

```bash
./gradlew build check cleanTest test --console=rich
```

# Other Docs

* [Guidelines](./CONVENTIONS.md)
* [Code of Conduct](./CODE_OF_CONDUCT.md)
* [Governance](./GOVERNANCE.md)
