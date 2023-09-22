package web5.common

import java.io.DataInput
import java.io.IOException


public object Varint {
  public fun encode(inp: Int): ByteArray {
    var value = inp
    val byteArrayList = ByteArray(10)
    var i = 0
    while (value and 0xFFFFFF80.toInt() != 0) {
      byteArrayList[i++] = ((value and 0x7F) or 0x80).toByte()
      value = value ushr 7
    }
    byteArrayList[i] = (value and 0x7F).toByte()
    val out = ByteArray(i + 1)
    while (i >= 0) {
      out[i] = byteArrayList[i]
      i--
    }

    return out
  }

  public fun decode(input: ByteArray): Pair<Int, Int> {
    var value = 0
    var i = 0
    var bytesRead = 0
    var b: Int

    while (true) {
      b = input[bytesRead].toInt()
      bytesRead++

      if (b and 0x80 == 0) break

      value = value or (b and 0x7F shl i)
      i += 7
      require(i <= 35) { "Variable length quantity is too long" }
    }

    value = value or (b shl i)

    return Pair(value, bytesRead)
  }
}