# web5-sdk-kotlin

[![License](https://img.shields.io/github/license/TBD54566975/web5-kt)](https://github.com/TBD54566975/web5-kt/blob/main/LICENSE)
[![SDK Kotlin CI](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml/badge.svg)](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml) [![Coverage](https://img.shields.io/codecov/c/gh/tbd54566975/web5-kt/main?logo=codecov&logoColor=FFFFFF&style=flat-square&token=YI87CKF1LI)](https://codecov.io/github/TBD54566975/web5-kt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/TBD54566975/web5-kt/badge)](https://securityscorecards.dev/viewer/?uri=github.com/TBD54566975/web5-kt)

This repo contains 5 packages:

- [common](./common) - Utilities for encoding, decoding, and hashing
- [crypto](./crypto) - Key generation, signing, signature verification, encryption, and decryption
- [dids](./dids) - Decentralized Identifier generation and resolution
- [credentials](./credentials) - Creation and verification of verifiable claims
- [web5](./web5) - The full Web5 platform

# Quickstart

Web5 is available
[from Maven Central](https://central.sonatype.com/artifact/xyz.block/web5). Instructions for
adding the dependency in a variety of build tools including Maven and Gradle are linked there.

> [!IMPORTANT]
> Web5 contains transitive dependencies not
> found in Maven Central. To resolve these, add the
> [TBD thirdparty repository](https://blockxyz.jfrog.io/artifactory/tbd-oss-thirdparty-maven2/)
> to your Maven or Gradle config.
>
> For instance, in your Maven `pom.xml`:
>
> ```shell
> <repositories>
>   <repository>
>     <id>tbd-oss-thirdparty</id>
>     <name>tbd-oss-thirdparty</name>
>     <releases>
>       <enabled>true</enabled>
>     </releases>
>     <snapshots>
>       <enabled>false</enabled>
>     </snapshots>
>     <url>https://blockxyz.jfrog.io/artifactory/tbd-oss-thirdparty-maven2/</url>
>   </repository>
> </repositories>
> ```
>
> ...or in your `gradle.settings.kts`:
>
> ```shell
> dependencyResolutionManagement {
>   repositories {
>       mavenCentral()
>       // Thirdparty dependencies of TBD projects not in Maven Central
>       maven("https://blockxyz.jfrog.io/artifactory/tbd-oss-thirdparty-maven2/")
> }
> ```

# Examples

Examples are hosted in the public documentation for each module, which is hosted
in [GitHub Pages](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/).

# Development

## Prerequisites

### Cloning

This repository uses git submodules. To clone this repo with submodules

```sh
git clone --recurse-submodules git@github.com:TBD54566975/web5-kt.git
```

Or to add submodules after cloning

```sh
git submodule update --init
```

We recommend this config which will only checkout the files relevant to web5-kt

```sh
git -C web5-spec sparse-checkout set test-vectors
```

### Hermit

This project uses hermit to manage tooling like Maven and Java versions.
See [this page](https://cashapp.github.io/hermit/usage/get-started/) to set up Hermit on your machine - make sure to
download the open source build and activate it for the project.

Once you've installed Hermit and before running builds on this repo,
run from the root:

```shell
source ./bin/activate-hermit
```

This will set your environment up correctly in the
terminal emulator you're on.

## Building with Maven

This project is built with the
[Maven Project Management](https://maven.apache.org/) tool.
It is installed via Hermit above.

If you want to build an artifact on your local filesystem, you can do so by running the
following command - either at the top level or in
any of the subprojects:

```shell
mvn clean verify
```

This will first clean all previous builds and compiled code, then:
compile, test, and build the artifacts in each of the submodules
of this project in the `$moduleName/target` directory, for example:

```shell
ls -l crypto/target/
```

You should see similar to:

```shell
total 96
drwxr-xr-x@ 4 alr  staff    128 Mar  8 02:33 classes
drwxr-xr-x@ 4 alr  staff    128 Mar  8 02:33 generated-sources
drwxr-xr-x@ 4 alr  staff    128 Mar  8 02:33 kaptStubs
drwxr-xr-x@ 4 alr  staff    128 Mar  8 02:33 kotlin-ic
drwxr-xr-x@ 3 alr  staff     96 Mar  8 02:34 maven-archiver
drwxr-xr-x@ 3 alr  staff     96 Mar  8 02:33 maven-status
drwxr-xr-x@ 8 alr  staff    256 Mar  8 02:34 surefire-reports
drwxr-xr-x@ 4 alr  staff    128 Mar  8 02:33 test-classes
-rw-r--r--@ 1 alr  staff  46314 Mar  8 02:34 web5-crypto-0.13.0-SNAPSHOT.jar
```

If you'd like to skip packaging and test only, run:

```shell
mvn test
```

You may also run a single test; `cd` into the submodule of choice,
then use the `-Dtest=` parameter to denote which test to run, for example:

```shell
cd crypto; \
mvn test -Dtest=TestClassName
```

To install builds into your local Maven repository, run from the root:

```shell
mvn install
```

For more, see the documentation on [Maven Lifecycle](https://maven.apache.org/guides/introduction/introduction-to-the-lifecycle.html).

## Generating API Docs Locally

We use [Dokka](https://kotlinlang.org/docs/dokka-cli.html) to create the
HTML API Documentation for this project. This is done using the Dokka CLI
because the [Dokka Maven Plugin](https://kotlinlang.org/docs/dokka-maven.html)
does not yet support multimodule builds. To run locally, obtain the Dokka CLI.
Run from the root of this repo:

```shell
# it will download the jars into the `target/dokka-cli` folder and generate the docs
./scripts/dokka.sh
```

These will be available in `target/apidocs`.

This step is handled during releases and published via GitHub Actions.

## Publishing Docs

API reference documentation is automatically updated are available
at [https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/](https://tbd54566975.github.io/web5-kt/docs/htmlMultiModule/)
following each automatically generated release.

## Dependency Management

As Web5 is a platform intended to run in a single `ClassLoader`,
versions and dependencies must be aligned among the subprojects
(sometimes called modules) of this project. To address, we declare
versions in `pom.xml`'s `<dependencyManagement>` section and
import references defined there in the subproject `pom.xml`s' `<dependencies>`
sections. Versions themselves are defined as properties in the root `pom.xml`.
See further documentation on versioning and dependency management there.

The root `pom.xml` may also be imported in projects building atop
Web5 in `import` scope to respect these dependency declaarations.

## Release Guidelines

### Pre-releases

In Kotlin we use the SNAPSHOT convention to build and publish a pre-release package that can be consumed for preview/testing/development purposes.

These SNAPSHOTs are generated and published whenever there's a new push to `main`. If you want to manually kick that off to preview some changes introduced in a PR branch:

1. Open the [SDK Kotlin CI Workflow](https://github.com/TBD54566975/web5-kt/actions/workflows/ci.yml), press the **Run workflow button** selecting the branch you want to generate the snapshot from.

2. In the version field, insert the current version, a short meaningful identifier and the `-SNAPSHOT` suffix, ie:

   - 0.11.0.pr123-SNAPSHOT
   - 0.11.0.shortsha-SNAPSHOT
   - 0.11.0.fixsomething-SNAPSHOT

3. Run workflow!

You **MUST** use the `-SNAPSHOT` suffix, otherwise it's not a valid preview `SNAPSHOT` and it will be rejected.

`SNAPSHOT`s will be available in [TBD's Artifactory `tbd-oss-snapshots-maven2` Repository](https://blockxyz.jfrog.io/artifactory/tbd-oss-snapshots-maven2).

### Releasing New Versions

To release a new version, execute the following steps:

1. Open the [Release and Publish](https://github.com/TBD54566975/web5-kt/actions/workflows/release.yml), press the **Run workflow button** selecting the branch you want to generate the snapshot from.

2. In the version field, declare the version to be released. ie:

   - 0.15.2
   - 0.17.0-alpha-3
   - 1.6.3

   - **Choose an appropriate version number based on semver rules. Remember that versions are immutable once published to Maven Central; they cannot be altered or removed.**

3. Press the **Run workflow button** and leave the main branch selected (unless its a rare case where you don't want to build from the main branch for the release).

4. Run workflow! This:

- Builds
- Tests
- Creates artifacts for binaries and sources
- Signs artifacts
- Uploads artifacts to TBD Artifactory
- Tags git with release number "v$version"
- Keeps development version in the pom.xml to 0.0.0-main-SNAPSHOT
- Pushes changes to git
- Triggers job to:
  - Build from tag and upload to Maven Central
  - Create GitHub Release "v$version"built and **published to maven central**, **docs will be published** (see below) and **the GitHub release will be automatically generated**!
  - Publish API Docs

### Publishing a `SNAPSHOT` from a Local Dev Machine

Please take care to only publish `-SNAPSHOT` builds (ie.
when the `<version>` field of the `pom.xml` ends in
`-SNAPSHOT`.) unless there's good reason
to deploy a non-`SNAPSHOT` release. Releases are typically handled via automation
in GitHub Actions s documented above.

To deploy to TBD's Artifactory instance for sharing with others, you
need your Artifactory username and password handy (available to TBD-employed engineers).
Set environment variables:

```shell
export ARTIFACTORY_USERNAME=yourUsername; \
export ARTIFACTORY_PASSWORD=yourPassword
```

...then run:

```shell
mvn deploy --settings .maven_settings.xml
```

## Working with the `web5-spec` submodule

### Pulling

You may need to update the `web5-spec` submodule after pulling.

```sh
git pull
git submodule update
```

### Pushing

If you have made changes to the `web5-spec` submodule, you should push your changes to the `web5-spec` remote as well as
pushing changes to `web5-kt`.

```sh
cd web5-spec
git push
cd ..
git push
```

# Other Docs

- [Guidelines](./CONVENTIONS.md)
- [Code of Conduct](./CODE_OF_CONDUCT.md)
- [Governance](./GOVERNANCE.md)
