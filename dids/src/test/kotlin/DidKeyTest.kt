import org.junit.jupiter.api.Test
import web5.dids.DidKey

class DidKeyTest {
  @Test
  fun `it works`() {
    val result = DidKey.create()
    println(result.first)
  }
}