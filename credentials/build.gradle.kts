plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
  // block's cache artifactory for tbd's oss third party dependencies
  // that do not live in maven central
  maven {
    name = "tbd-oss-thirdparty"
    url = uri("https://blockxyz.jfrog.io/artifactory/tbd-oss-thirdparty-maven2/")
    mavenContent {
      releasesOnly()
    }
  }
}

dependencies {
  /**
   * Maintainers - please do not declare versioning here at the module level;
   * versioning is centralized for the platform in $projectRoot/gradle/libs.versions.toml
   *
   * Deps are declared in alphabetical order.
   */

  // API
  /*
   * API Leak: https://github.com/TBD54566975/web5-kt/issues/228
   *
   * Change and move to "implementation" when completed
   */
  api(libs.comDanubetechVerifiableCredentials)

  // Project
  implementation(project(":dids"))
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation(project(":jose"))


  // Implementation
  implementation(libs.comFasterXmlJacksonModuleKotlin)
  implementation(libs.comNetworkntJsonSchemaValidator)
  implementation(libs.comNfeldJsonpathkt)
  implementation(libs.comNimbusdsJoseJwt)
  implementation(libs.bundles.ioKtorForCredentials)

  // Test
  /**
   * Test dependencies may declare direct versions; they are not exported
   * and therefore are within the remit of this module to self-define
   * if desired.
   */
  testImplementation(libs.ioKtorClientMock)
  testImplementation(kotlin("test"))
  testImplementation(libs.comWillowtreeappsAssertk)
  testImplementation(project(":testing"))
}