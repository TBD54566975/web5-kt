package web5.sdk.common

import java.io.ByteArrayOutputStream
import kotlin.experimental.and

public object ZBase32 {
  private val enc = "ybndrfg8ejkmcpqxot1uwisza345h769"
  private val dec = IntArray(128)

  init {
    for (i in dec.indices) {
      dec[i] = -1
    }
    for (i in enc.indices) {
      dec[enc[i].code] = i
    }
  }

  public fun encode(data: ByteArray): String {
    var buffer = 0
    var bufferLength = 0
    val result = StringBuilder()

    for (byte in data) {
      buffer = (buffer shl 8) + (byte.toInt() and 0xFF)
      bufferLength += 8

      while (bufferLength >= 5) {
        val charIndex = (buffer shr (bufferLength - 5)) and 0x1F
        result.append(enc[charIndex])
        bufferLength -= 5
      }
    }

    // If there are any bits left, we need to append an encoded character for them
    if (bufferLength > 0) {
      // This means there were not enough bits to make a full 5 bit group
      buffer = buffer shl (5 - bufferLength)
      val charIndex = buffer and 0x1F
      result.append(enc[charIndex])
    }

    // Remove unnecessary padding characters but keep meaningful 'y'
    while (result.length > 1 && result.last() == 'y') {
      result.setLength(result.length - 1)
    }

    return result.toString()
  }

  public fun decode(data: String): ByteArray {
    var buffer = 0
    var bufferLength = 0
    val result = ByteArrayOutputStream()

    for (char in data) {
      val index = dec[char.toInt()]
      if (index == -1) throw IllegalArgumentException("Invalid zbase32 character: $char")

      buffer = (buffer shl 5) + index
      bufferLength += 5

      while (bufferLength >= 8) {
        val byte = (buffer shr (bufferLength - 8)) and 0xFF
        result.write(byte)
        bufferLength -= 8
      }
    }

    if (bufferLength > 0) {
      val actualBits = 8 - (data.length * 5 % 8) % 8
      val byte = (buffer shl (actualBits)) and 0xFF
      result.write(byte)
    }

    return result.toByteArray()
  }

}
