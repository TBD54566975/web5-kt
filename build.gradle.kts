import io.gitlab.arturbosch.detekt.Detekt
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URL

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.22"
  id("base")
  id("io.gitlab.arturbosch.detekt") version "1.23.+"
  `maven-publish`
  id("org.jetbrains.dokka") version "1.9.+"
  id("org.jetbrains.kotlinx.kover") version "0.7.+"
  signing
  idea
  id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
  id("version-catalog")
}

allprojects {
  configurations.all {
    /**
     * In this section we address build issues including security vulnerabilities
     * in transitive dependencies we don't explicitly declare in
     * `gradle/libs.versions.toml`. Forced actions taken here will override any
     * declarations we make, so use with care. Also note: these are in place for a
     * point in time. As we maintain this software, the manual forced resolution we do
     * here may:
     *
     * 1) No longer be necessary (if we have removed a dependency path leading to dep)
     * 2) Break an upgrade (if we upgrade a dependency and this forces a lower version
     *    of a transitive dependency it brings in)
     *
     * So we need to exercise care here, and, when upgrading our deps, check to see if
     * these forces aren't breaking things.
     *
     * When adding forces here, please reference the issue which explains why we
     * needed to do this; it will help future maintainers understand if the force
     * is still valid, should be removed, or handled in another way.
     *
     * When in doubt, ask! :)
     */
    resolutionStrategy {
      // Pin the transitive dep to a version that's not vulnerable.
      force("com.fasterxml.woodstox:woodstox-core:6.4.0")
      // Addresss https://github.com/TBD54566975/web5-kt/issues/242
      force("com.google.protobuf:protobuf-javalite:3.19.6")
      // Addresss https://github.com/TBD54566975/web5-kt/issues/243
      force("com.google.guava:guava:32.0.0-android")
      // Addresses https://github.com/TBD54566975/web5-kt/issues/244
      force("com.squareup.okio:okio:3.6.0")
    }
  }
}

repositories {
  mavenCentral()
}

dependencies {
  api(project(":common"))
  api(project(":credentials"))
  api(project(":crypto"))
  api(project(":dids"))

  detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.+")
}

allprojects {
  group = "xyz.block"
  tasks.findByName("wrapper")?.enabled = false
}

subprojects {
  repositories {
    mavenCentral()
    maven("https://jitpack.io")
  }

  apply {
    plugin("io.gitlab.arturbosch.detekt")
    plugin("org.jetbrains.kotlin.jvm")
    plugin("java-library")
    plugin("maven-publish")
    plugin("org.jetbrains.dokka")
    plugin("org.jetbrains.kotlinx.kover")
    plugin("signing")
    plugin("idea")
  }

  configurations.all {
    resolutionStrategy {
      // Pin the transitive dep to a version that's not vulnerable.
      force("com.fasterxml.woodstox:woodstox-core:6.4.0")
    }
  }

  tasks.withType<Detekt>().configureEach {
    jvmTarget = "1.8"
  }

  sourceSets {
    create("intTest") {
      compileClasspath += sourceSets.main.get().output
      runtimeClasspath += sourceSets.main.get().output
    }
  }

  val intTestImplementation by configurations.getting {
    extendsFrom(configurations.implementation.get())
  }
  val intTestRuntimeOnly by configurations.getting

  configurations["intTestRuntimeOnly"].extendsFrom(configurations.runtimeOnly.get())

  dependencies {
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.4")
    detektPlugins("com.github.TBD54566975:tbd-detekt-rules:v0.0.2")

    testImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    intTestImplementation(kotlin("test"))
    intTestImplementation("org.junit.jupiter:junit-jupiter:5.9.2")
    intTestRuntimeOnly("org.junit.platform:junit-platform-launcher")
  }

  idea {
    module {
      testSources.from(sourceSets["intTest"].java.srcDirs)
      testSources.from(sourceSets["intTest"].kotlin.srcDirs)
    }
  }

  val integrationTest = task<Test>("integrationTest") {
    description = "Runs integration tests."
    group = "verification"

    testClassesDirs = sourceSets["intTest"].output.classesDirs
    classpath = sourceSets["intTest"].runtimeClasspath
    shouldRunAfter("test")

    useJUnitPlatform()

    testLogging {
      events("passed", "skipped", "failed", "standardOut", "standardError")
      exceptionFormat = TestExceptionFormat.FULL
      showExceptions = true
      showCauses = true
      showStackTraces = true
    }
  }

  tasks.check { dependsOn(integrationTest) }

  detekt {
    config.setFrom("$rootDir/config/detekt.yml")
  }

  kotlin {
    explicitApi()
    jvmToolchain(11)
    compilerOptions {
      jvmTarget.set(JvmTarget.JVM_11)
      apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
      languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
    }
  }

  java {
    withJavadocJar()
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }

  val publicationName = "${rootProject.name}-${project.name}"
  publishing {
    publications {
      create<MavenPublication>(publicationName) {
        groupId = project.group.toString()
        artifactId = name
        description = name
        version = project.property("version").toString()
        from(components["java"])
      }
      withType<MavenPublication> {
        pom {
          name = publicationName
          packaging = "jar"
          description.set("Web5 SDK for the JVM")
          url.set("https://github.com/TBD54566975/web5-kt")
          inceptionYear.set("2023")
          licenses {
            license {
              name.set("The Apache License, Version 2.0")
              url.set("https://github.com/TBD54566975/web5-kt/blob/main/LICENSE")
            }
          }
          developers {
            developer {
              id.set("TBD54566975")
              name.set("Block Inc.")
              email.set("tbd-releases@tbd.email")
            }
          }
          scm {
            connection.set("scm:git:git@github.com:TBD54566975/web5-kt.git")
            developerConnection.set("scm:git:ssh:git@github.com:TBD54566975/web5-kt.git")
            url.set("https://github.com/TBD54566975/web5-kt")
          }
        }
      }
    }

    if (!project.hasProperty("skipSigning") || project.property("skipSigning") != "true") {
      signing {
        val signingKey: String? by project
        val signingPassword: String? by project
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications[publicationName])
      }
    }
  }

  tasks.withType<DokkaTaskPartial>().configureEach {
    dokkaSourceSets.configureEach {
      documentedVisibilities.set(
        setOf(
          DokkaConfiguration.Visibility.PUBLIC,
          DokkaConfiguration.Visibility.PROTECTED
        )
      )

      includes.from("${projectDir}/module.md")

      sourceLink {
        val exampleDir = "https://github.com/TBD54566975/web5-kt/tree/main"

        localDirectory.set(rootProject.projectDir)
        remoteUrl.set(URL(exampleDir))
        remoteLineSuffix.set("#L")
      }
    }
  }

  tasks.test {
    useJUnitPlatform()
    reports {
      junitXml
    }
    testLogging {
      events("passed", "skipped", "failed", "standardOut", "standardError")
      exceptionFormat = TestExceptionFormat.FULL
      showExceptions = true
      showCauses = true
      showStackTraces = true
    }
  }
}

// Configures only the parent MultiModule task,
// this will not affect subprojects
tasks.dokkaHtmlMultiModule {
  moduleName.set("Web5 SDK Documentation")
}

publishing {
  publications {
    create<MavenPublication>("web5") {
      groupId = project.group.toString()
      artifactId = name
      description = "Web5 SDK for the JVM"
      version = project.property("version").toString()
      from(components["java"])

      pom {
        packaging = "pom"
        name = "Web5 SDK for the JVM"
        description.set("Web5 SDK for the JVM")
        url.set("https://github.com/TBD54566975/web5-kt")
        inceptionYear.set("2023")
        licenses {
          license {
            name.set("The Apache License, Version 2.0")
            url.set("https://github.com/TBD54566975/web5-kt/blob/main/LICENSE")
          }
        }
        developers {
          developer {
            id.set("TBD54566975")
            name.set("Block Inc.")
            email.set("tbd-releases@tbd.email")
          }
        }
        scm {
          connection.set("scm:git:git@github.com:TBD54566975/web5-kt.git")
          developerConnection.set("scm:git:ssh:git@github.com:TBD54566975/web5-kt.git")
          url.set("https://github.com/TBD54566975/web5-kt")
        }
      }
    }
  }
}

if (!project.hasProperty("skipSigning") || project.property("skipSigning") != "true") {
  signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["web5"])
  }
}

nexusPublishing {
  repositories {
    sonatype {  //only for users registered in Sonatype after 24 Feb 2021
      nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
      snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
    }
  }
}
