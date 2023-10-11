plugins {
  id("org.jetbrains.kotlin.jvm")
  id("java-library")
}

version = "0.1.0"

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(kotlin("test"))
  testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
}

tasks.test {
  useJUnitPlatform()
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