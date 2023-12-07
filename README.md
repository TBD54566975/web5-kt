# web5-sdk-kotlin

[![License](https://img.shields.io/github/license/TBD54566975/web5-kt)](https://github.com/TBD54566975/web5-kt/blob/main/LICENSE)
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
  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
  maven("https://repository.jboss.org/nexus/content/repositories/thirdparty-releases/")
}

dependencies {
  implementation("com.github.TBD54566975:web5-kt:main-SNAPSHOT")
}
```

> [!IMPORTANT]
> The repository at `https://repo.danubetech.com/repository/maven-public/` is required for resolving transitive
dependencies.

If you want to refer to a specific release, then replace the `main-SNAPSHOT` with release tag.

If you want to pull a PR, then replace `main-SNAPSHOT` using the template `PR<NR>-SNAPSHOT`. For
example `PR40-SNAPSHOT`.

If you want to depend on a single module, like `credentials`, then use the following dependencies

```kotlin
dependencies {
  implementation("com.github.TBD54566975.web5-kt:credentials:master-SNAPSHOT")
}
```

# Examples

Examples are hosted in the public documentation for each module, which is hosted
in [GitHub Pages](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/credentials/index.html).

# Development

## Prerequisites

Install java version 11. If you're installing a higher version, it must be compatible with Gradle 8.2.

If you want to have multiple version of Java installed in your machine, we recommend using [jenv](https://www.jenv.be/).

> [!NOTE]: Restart your shell after installation.

## Build

To build and run test just run:

```bash
./gradlew build --console=rich
```

## Releasing

In order to release to Central Repository, simply cut a new release tag in the Github UI. There is a configured [Github
Action](./.github/workflows/publish.yml) that will automatically publish the release to Central Repository. You can cut
the release by going to the [create a new releases page](https://github.com/TBD54566975/web5-kt/releases/new). When
creating a new tag, the name should be in the format `vX.Y.Z`. Please note that once a release is made, it is immutable
and cannot be deleted.

### Manual Release

If you want to do a manual release, you have two options:
1. Dispatch the [publish workflow](./.github/workflows/publish.yml) workflow from the Github UI. Go to the [publish 
   Actions](https://github.com/TBD54566975/web5-kt/actions) > "Run workflow". 
2. Setup your local environment to publish to Central Repository. This is more involved. You'll need to:
   1. Define all the environment variables described in the [publish workflow](./.github/workflows/publish.yml) file. You
      can find the values in the [secrets and variable](https://github.com/TBD54566975/web5-kt/settings/secrets/actions)
      page.
   2. Run the following command (you can change `samplebranch` to any branch name):
      ```bash
      ./gradlew -Pversion=samplebranch-SNAPSHOT publishToSonatype closeAndReleaseSonatypeStagingRepository
      ```

# Other Docs

* [Guidelines](./CONVENTIONS.md)
* [Code of Conduct](./CODE_OF_CONDUCT.md)
* [Governance](./GOVERNANCE.md)
