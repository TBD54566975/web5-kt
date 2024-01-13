# web5-sdk-kotlin

[![License](https://img.shields.io/github/license/TBD54566975/web5-kt)](https://github.com/TBD54566975/web5-kt/blob/main/LICENSE)
[![SDK Kotlin CI](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml/badge.svg)](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/codecov/c/gh/tbd54566975/web5-kt/main?logo=codecov&logoColor=FFFFFF&style=flat-square&token=YI87CKF1LI)](https://codecov.io/github/TBD54566975/web5-kt)

This repo contains 4 jvm packages:

* [common](./common) - utilities for encoding, decoding, and hashing
* [crypto](./crypto) - key generation, signing, signature verification, encryption, and decryption
* [dids](./dids) - did generation and resolution
* [credentials](./credentials) - creation and verification of verifiable claims

# Quickstart

You can add this library to your project using Gradle or Maven. To do so, pull the package from Maven Central.

## Maven Central

When pulling from Maven Central, you can pull the entire library or just a single module. Examples of both are shown
below. Please note that you need to add the repositories shown below to your `build.gradle.kts` file. This is because
the libraries that we depend on are hosted in separate places.

```kt
repositories {
  mavenCentral()
  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
}

dependencies {
  // If you want to pull the entire library
  implementation("xyz.block:web5:0.1.0")

  // If you want to pull a single module
  implementation("xyz.block:web5-common:0.1.0")
  implementation("xyz.block:web5-credentials:0.1.0")
  implementation("xyz.block:web5-crypto:0.1.0")
  implementation("xyz.block:web5-dids:0.1.0")
}
```

> [!IMPORTANT]
> Additional repositories, like `https://repo.danubetech.com/repository/maven-public/`, are required for resolving
transitive dependencies.

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
