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

  /*
   * API Leak: https://github.com/TBD54566975/web5-kt/issues/230
   *
   * Change and move to "implementation" when completed
   */
  api(libs.comAmazonawsAwsKms)

  // Project
  implementation(project(":common"))

  // Implementation
  implementation(libs.comGoogleCryptoTink)
  implementation(libs.bundles.orgBouncycastle)
  implementation(libs.comFasterXmlJacksonModuleKotlin)
  implementation(libs.comNimbusdsJoseJwt)

  // Test
  /**
   * Test dependencies may declare direct versions; they are not exported
   * and therefore are within the remit of this module to self-define
   * if desired.
   */
  testImplementation(kotlin("test"))
  testImplementation(project(":testing"))
}