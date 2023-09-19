import io.gitlab.arturbosch.detekt.Detekt

plugins {
  id("org.jetbrains.kotlin.jvm") version "1.9.0"
  id("java-library")
  id("io.gitlab.arturbosch.detekt").version("1.23.1")
}

repositories {
  mavenCentral()
}

dependencies {
  detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.23.1")
}

subprojects {
  apply {
    plugin("io.gitlab.arturbosch.detekt")
    plugin("org.jetbrains.kotlin.jvm")
    plugin("java-library")
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
}