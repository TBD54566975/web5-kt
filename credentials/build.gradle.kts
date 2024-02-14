plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
  // temp maven repo for danubetech
  maven {
    name = "tbd-danubetech-temp"
    url = uri("https://blockxyz.jfrog.io/artifactory/danubetech-temp/")
    mavenContent {
      releasesOnly()
    }
  }
  maven("https://jitpack.io")
  maven("https://repo.danubetech.com/repository/maven-public/")
  maven("https://repository.jboss.org/nexus/content/repositories/thirdparty-releases/")
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

  // Implementation
  implementation(libs.comFasterXmlJacksonModuleKotlin)
  implementation(libs.comNetworkntJsonSchemaValidator)
  implementation(libs.comNfeldJsonpathkt)
  implementation(libs.comNimbusdsJoseJwt)
  implementation(libs.decentralizedIdentityDidCommonJava)
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