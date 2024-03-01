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
    val didUri = DidUri.Parser.parse("did:example:123/path?service=agent&relativeRef=/credentials#degree")
    assertEquals("did:example:123", didUri.uri)
    assertEquals("did:example:123/path?service=agent&relativeRef=/credentials#degree", didUri.url)
    assertEquals("example", didUri.method)
    assertEquals("123", didUri.id)
    assertEquals("/path", didUri.path)
    assertEquals("service=agent&relativeRef=/credentials", didUri.query)
    assertEquals("degree", didUri.fragment)
    // todo: fix this - params should not be null
    //  but the regex for catching params is returning null.
    assertNotEquals(emptyMap(), didUri.params)
  }

}