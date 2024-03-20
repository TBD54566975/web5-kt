package web5.sdk.dids.didcore

import org.junit.jupiter.api.assertThrows
import kotlin.test.Test
import kotlin.test.assertEquals

class ServiceTest {

  @Test
  fun `Builder works`() {
    val service = Service.Builder()
      .id("did:example:123#key-1")
      .type("PFI")
      .serviceEndpoint(listOf("https://example.com/"))
      .build()
    assertEquals("did:example:123#key-1", service.id)
    assertEquals("PFI", service.type)
    assertEquals(listOf("https://example.com/"), service.serviceEndpoint)
    assertEquals(
      "Service(" +
        "id='did:example:123#key-1', " +
        "type='PFI', " +
        "serviceEndpoint=[https://example.com/])",
      service.toString()
    )
  }

  @Test
  fun `build() throws exception if id is not set`() {

    assertThrows<IllegalStateException> {
      Service.Builder()
        .type("PFI")
        .serviceEndpoint(listOf("https://example.com/"))
        .build()
    }
  }

  @Test
  fun `build() throws exception if type is not set`() {

    assertThrows<IllegalStateException> {
      Service.Builder()
        .id("did:example:123#key-1")
        .serviceEndpoint(listOf("https://example.com/"))
        .build()
    }
  }

  @Test
  fun `build() throws exception if serviceEndpoint is not set`() {

    assertThrows<IllegalStateException> {
      Service.Builder()
        .id("did:example:123#key-1")
        .type("PFI")
        .build()
    }
  }


}