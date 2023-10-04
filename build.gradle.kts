import io.gitlab.arturbosch.detekt.Detekt
import org.jetbrains.dokka.DokkaConfiguration
import org.jetbrains.dokka.gradle.DokkaTaskPartial
import java.net.URL

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.0"
  id("java-library")
  id("io.gitlab.arturbosch.detekt") version "1.23.1"
  `maven-publish`
  id("org.jetbrains.dokka") version "1.9.0"
  id("org.jetbrains.kotlinx.kover") version "0.7.3"
}

repositories {
  mavenCentral()
}

dependencies {
  detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.1")
}

allprojects {
  version = "0.0.0"
  group = "web5"
}

subprojects {
  apply {
    plugin("io.gitlab.arturbosch.detekt")
    plugin("org.jetbrains.kotlin.jvm")
    plugin("java-library")
    plugin("maven-publish")
    plugin("org.jetbrains.dokka")
    plugin("org.jetbrains.kotlinx.kover")
  }

  tasks.withType<Detekt>().configureEach {
    jvmTarget = "1.8"
  }
  dependencies {
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.1")
  }

  detekt {
    config.setFrom("$rootDir/config/detekt.yml")
  }

  kotlin {
    explicitApi()
  }

  java {
    withJavadocJar()
    withSourcesJar()
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

      sourceLink {
        val exampleDir = "https://github.com/TBD54566975/web5-sdk-kotlin/tree/main"

        localDirectory.set(rootProject.projectDir)
        remoteUrl.set(URL(exampleDir))
        remoteLineSuffix.set("#L")
      }
    }
  }
}

// Configures only the parent MultiModule task,
// this will not affect subprojects
tasks.dokkaHtmlMultiModule {
  moduleName.set("Web5 SDK Documentation")
}