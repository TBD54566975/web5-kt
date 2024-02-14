plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
  maven("https://repo.danubetech.com/repository/maven-public")
  maven("https://jitpack.io")
  maven("https://jcenter.bintray.com/")
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
   * API Leak: https://github.com/TBD54566975/web5-kt/issues/231
   *
   * Change and move to "implementation" when completed
   */
//  api(libs.decentralizedIdentityDidCommonJava)

  // Project
  implementation(project(":common"))
  implementation(project(":crypto"))

  // Implementation
  implementation(libs.comFasterXmlJacksonModuleKotlin)
  implementation(libs.comNimbusdsJoseJwt)
  implementation(libs.comGithubMultiformats)
  implementation(libs.comSquareupOkhttp3)
  implementation(libs.dnsJava)
  implementation(libs.ioGithubErdtmanJavaJsonCanonicalization)
  implementation(libs.ioGithubOshaiKotlinLogging)
  implementation(libs.bundles.ioKtorForDids)

  // Test
  /**
   * Test dependencies may declare direct versions; they are not exported
   * and therefore are within the remit of this module to self-define
   * if desired.
   */
  testImplementation(kotlin("test"))
  testImplementation(libs.ioKtorClientMock)
  testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
  testImplementation("commons-codec:commons-codec:1.16.0")
  testImplementation(project(mapOf("path" to ":testing")))
}