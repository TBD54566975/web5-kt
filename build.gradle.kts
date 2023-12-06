import io.gitlab.arturbosch.detekt.Detekt
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jreleaser.model.Active
import java.net.URL

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.0"
  id("java-library")
  id("io.gitlab.arturbosch.detekt") version "1.23.1"
  `maven-publish`
  id("org.jetbrains.dokka") version "1.9.0"
  id("org.jetbrains.kotlinx.kover") version "0.7.3"
  signing
  id("org.jreleaser") version "1.9.0"
  idea
}

repositories {
  mavenCentral()
}

dependencies {
  detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.1")
}

allprojects {
  version = "0.0.9"
  group = "xyz.block"
}

subprojects {
  apply {
    plugin("io.gitlab.arturbosch.detekt")
    plugin("org.jetbrains.kotlin.jvm")
    plugin("java-library")
    plugin("maven-publish")
    plugin("org.jetbrains.dokka")
    plugin("org.jetbrains.kotlinx.kover")
    plugin("maven-publish")
    plugin("signing")
    plugin("org.jreleaser")
    plugin("idea")
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
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.1")

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

  publishing {
    publications {
      create<MavenPublication>("web5") {
        groupId = project.group.toString()
        artifactId = project.name
        version = project.version.toString()
        description = "Kotlin SDK for web5 functionality"
        from(components["java"])
      }
      withType<MavenPublication> {
        pom {
          packaging = "jar"
          name.set("web5-" + project.name)
          description.set("web5 kotlin SDK")
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

    repositories {
      maven {
        url = layout.buildDirectory.dir("staging-deploy").get().asFile.toURI()
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

  signing {
    sign(publishing.publications["web5"])
  }

  tasks.test {
    useJUnitPlatform()
    testLogging {
      events("passed", "skipped", "failed", "standardOut", "standardError")
      exceptionFormat = TestExceptionFormat.FULL
      showExceptions = true
      showCauses = true
      showStackTraces = true
    }
  }

  jreleaser {
    project {
      copyright.set("Block Inc.")
    }
    gitRootSearch.set(true)
    signing {
      active.set(Active.ALWAYS)
      armored.set(true)
    }
    deploy {
      maven {
        nexus2 {
          create("maven-central") {
            active.set(Active.ALWAYS)
            url.set("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            snapshotUrl.set("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            closeRepository.set(false)
            releaseRepository.set(false)
            stagingRepositories.add("build/staging-deploy")
          }
        }
      }
    }
  }
}

// Configures only the parent MultiModule task,
// this will not affect subprojects
tasks.dokkaHtmlMultiModule {
  moduleName.set("Web5 SDK Documentation")
}
