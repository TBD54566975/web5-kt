import io.gitlab.arturbosch.detekt.Detekt
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.net.URL

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.0"
  id("java-library")
  id("io.gitlab.arturbosch.detekt") version "1.23.1"
  `maven-publish`
  id("org.jetbrains.dokka") version "1.9.0"
  id("org.jetbrains.kotlinx.kover") version "0.7.3"
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
  group = "web5"
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

  publishing {
    publications {
      create<MavenPublication>("web5") {
        groupId = project.group.toString()
        artifactId = project.name.toString()
        version = project.version.toString()
        from(components["java"])
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
