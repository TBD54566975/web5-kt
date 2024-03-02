package web5.sdk.dids.didcore

import org.junit.jupiter.api.assertThrows
import web5.sdk.dids.exceptions.ParserException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull

class DidUriTest {

  @Test
  fun `toString() returns url`() {
    val didUri = DidUri(
      uri = "did:example:123",
      url = "did:example:123#0",
      method = "example",
      id = "123",
      )
    assertEquals("did:example:123#0", didUri.toString())
  }

  @Test
  fun `Parser throws exception with invalid did`() {
    val exception = assertThrows<ParserException> {
      DidUri.Parser.parse("not-a-did")
    }
    assertEquals("Invalid DID URI", exception.message)
  }

  @Test
  fun `Parser parses a valid did`() {
    // todo adding /path after abcdefghi messes up the parsing of params (comes in null)
    val didUri = DidUri.Parser.parse("did:example:123456789abcdefghi;foo=bar;baz=qux?foo=bar&baz=qux#keys-1")
    assertEquals("did:example:123456789abcdefghi", didUri.uri)
    assertEquals("did:example:123456789abcdefghi;foo=bar;baz=qux?foo=bar&baz=qux#keys-1", didUri.url)
    assertEquals("example", didUri.method)
    assertEquals("123456789abcdefghi", didUri.id)
    assertEquals("foo=bar&baz=qux", didUri.query)
    assertEquals("keys-1", didUri.fragment)
    assertEquals(mapOf("foo" to "bar", "baz" to "qux"), didUri.params)
  }

}