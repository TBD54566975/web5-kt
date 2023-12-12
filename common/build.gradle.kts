plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
  testImplementation(project(mapOf("path" to ":crypto")))
}

java {
  withJavadocJar()
  withSourcesJar()
}

//mavenPublishing {
//  configure(KotlinJvm(
//    sourcesJar = true,
//    javadocJar = JavadocJar.Javadoc()
//  ))
//}