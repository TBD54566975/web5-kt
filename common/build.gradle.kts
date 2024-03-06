plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

dependencies {

  /**
   * Maintainers - please do not declare versioning here at the module level;
   * versioning is centralized for the platform in $projectRoot/gradle/libs.versions.toml
   *
   * Deps are declared in alphabetical order.
   */

  // API

  // Project

  // Implementation
  implementation(libs.comFasterXmlJacksonModuleKotlin)

  // Test
  /**
   * Test dependencies may declare direct versions; they are not exported
   * and therefore are within the remit of this module to self-define
   * if desired.
   */
  testImplementation(kotlin("test"))
}
