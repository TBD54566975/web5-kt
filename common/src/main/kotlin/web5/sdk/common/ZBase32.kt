package web5.sdk.common

import java.io.ByteArrayOutputStream

/**
 * ZBase32 is a variant of Base32 that is human-readable.
 * https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 */
public object ZBase32 {
  private const val alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
  private val decoder = IntArray(128)

  init {
    for (i in decoder.indices) {
      decoder[i] = -1
    }
    for (i in alphabet.indices) {
      decoder[alphabet[i].code] = i
    }
  }

  /**
   * Encodes the given data as a zbase32 string.
   * @param data the data to encode
   * @return the encoded string
   */
  public fun encode(data: ByteArray): String {
    if (data.isEmpty()) {
      return ""
    }
    var buffer = 0
    var bufferLength = 0
    val result = StringBuilder()
    for (b in data) {
      buffer = (buffer shl 8) + (b.toInt() and 0xFF)
      bufferLength += 8
      while (bufferLength >= 5) {
        val charIndex = buffer shr bufferLength - 5 and 0x1F
        result.append(alphabet[charIndex])
        bufferLength -= 5
      }
    }
    if (bufferLength > 0) {
      buffer = buffer shl 5 - bufferLength
      val charIndex = buffer and 0x1F
      result.append(alphabet[charIndex])
    }
    return result.toString()
  }

  /**
   * Decodes the given zbase32 string into a byte array.
   * @param data the data to decode
   * @return the decoded data
   */
  public fun decode(data: String): ByteArray {
    if (data.isEmpty()) {
      return ByteArray(0)
    }
    var buffer = 0
    var bufferLength = 0
    val result = ByteArrayOutputStream()
    for (c in data.toCharArray()) {
      val index = decoder[c.code]
      require(index != -1) { "Invalid zbase32 character: $c" }
      buffer = (buffer shl 5) + index
      bufferLength += 5
      while (bufferLength >= 8) {
        val b = (buffer shr bufferLength - 8 and 0xFF).toByte()
        result.write(b.toInt())
        bufferLength -= 8
      }
    }
    if (bufferLength > 0) {
      val paddingBits = data.length * 5 % 8
      if (paddingBits > 0) {
        val paddingBytes = (8 - paddingBits) / 8
        buffer = buffer shl paddingBits
        for (i in 0 until paddingBytes) {
          val b = (buffer shr bufferLength - 8 and 0xFF).toByte()
          result.write(b.toInt())
          bufferLength -= 8
        }
      }
    }
    return result.toByteArray()
  }

}
