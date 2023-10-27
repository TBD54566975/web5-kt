repositories {
  mavenCentral()
  maven {
    url = uri("https://repo.danubetech.com/repository/maven-public")
  }
  maven("https://jitpack.io")
}

dependencies {
  implementation("com.nimbusds:nimbus-jose-jwt:9.34")
  implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.13.4")
  implementation("org.bouncycastle:bcprov-jdk15on:1.70")

  testImplementation(project(":dids"))
  testImplementation(project(":crypto"))
  testImplementation("io.github.erdtman:java-json-canonicalization:1.1")
}

tasks.test {
  useJUnitPlatform()
}