plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

dependencies {

  // Project
  implementation(project(":common"))
  implementation(project(":crypto"))
  implementation(project(":dids"))

  // Test
  testImplementation(libs.comWillowtreeappsAssertk)
  testImplementation(kotlin("test"))
  testImplementation(project(":testing"))
}