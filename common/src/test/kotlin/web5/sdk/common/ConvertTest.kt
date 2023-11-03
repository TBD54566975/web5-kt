package web5.sdk.common

import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class ConvertTest {
  @Nested
  inner class StringTest {
    @Test
    fun toBase64Url() {
      val input = "foo";
      val expectedOutput = "Zm9v";

      val output = Convert(input).toBase64Url()
      assertEquals(output, expectedOutput)
    }

    @Test
    fun toZBase32() {
      // TODO: use test vectors from ZBase32Test
      val output = Convert("a").toZBase32()
      assertEquals("cr", output)

      val output2 = Convert("cr", EncodingFormat.ZBase32).toStr()
      assertEquals("a", output2)
    }
  }

}