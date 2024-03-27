plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "0.5.0"
}
rootProject.name = "web5"
include("common", "crypto", "dids", "credentials")
include("testing")
include("jose")
