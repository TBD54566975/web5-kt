import io.gitlab.arturbosch.detekt.Detekt

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.0"
  id("java-library")
  id("io.gitlab.arturbosch.detekt") version "1.23.1"
  `maven-publish`
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
}