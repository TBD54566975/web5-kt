package web5.sdk.dids.methods.web

import org.junit.jupiter.api.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LocalHostDomainMatcherTest {

  @Test
  fun testLocalHostDomains() {
    val domains = listOf(
      "localhost",
      "localhost:8080",
      "localhost/user/alice",
      "localhost:8080/user/alice",
      "127.0.0.1",
      "127.0.0.1:8080",
      "127.0.0.1/user/alice",
      "127.0.0.1:8080/user/alice",
    )
    domains.forEach {
      assertTrue(LocalHostDomainMatcher.isLocalHostDomain(it), "should be localhost domain: $it")
    }
  }

  @Test
  fun testNonLocalHostDomains() {
    val domains = listOf(
      "localhostx",
      "localhostx:8080",
      "localhostx/user/alice",
      "localhostx:8080/user/alice",
      "localhost.com",
      "notlocalhost",
      "127.0.0.10",
      "127.0.0.10:8080",
      "127.0.0.10/user/alice",
      "127.0.0.10:8080/user/alice",
    )
    domains.forEach {
      assertFalse(LocalHostDomainMatcher.isLocalHostDomain(it), "should not be localhost domain: $it")
    }
  }
}
