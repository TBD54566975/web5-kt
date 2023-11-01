package web5.sdk.common

import java.io.ByteArrayOutputStream

public object ZBase32 {
  private const val CHARSET = "ybndrfg8ejkmcpqxot1uwisza345h769"
  private val CHARSET_BYTES = CHARSET.toByteArray()
  private val dec = ByteArray(256)

  init {
    for (i in dec.indices) {
      dec[i] = 0xFF.toByte()
    }
    for (i in CHARSET.indices) {
      dec[CHARSET[i].code] = i.toByte()
    }
  }

  public fun encode(src: ByteArray): String {
    val dst = ByteArray(encodedLen(src.size))
    val n = encode(dst, src)
    return String(dst, 0, n, Charsets.UTF_8) // Assuming the encoding is UTF-8
  }

  private fun encodedLen(n: Int): Int {
    return (n + 4) / 5 * 8
  }

  private fun encode(dst: ByteArray, src: ByteArray): Int {
    return encode(dst, src, -1)
  }

  private fun encode(dst: ByteArray, src: ByteArray, bits: Int): Int {
    var off = 0
    var i = 0
    var localSrc = src.copyOf() // Copy to ensure we don't modify the original

    while (i < bits || (bits < 0 && localSrc.isNotEmpty())) {
      val b0 = localSrc[0]
      val b1 = if (localSrc.size > 1) localSrc[1] else 0.toByte()

      val offset = i % 8
      var char: Byte = when {
        offset < 4 -> (b0.toInt() and (31 shl (3 - offset)) shr (3 - offset)).toByte()
        else -> {
          var tempChar = b0.toInt() and (31 shr (offset - 3)) shl (offset - 3)
          tempChar = tempChar or (b1.toInt() and (255 shl (11 - offset)) shr (11 - offset))
          tempChar.toByte()
        }
      }

      // If src is longer than necessary, mask trailing bits to zero
      if (bits >= 0 && i + 5 > bits) {
        char = (char.toInt() and (255 shl ((i + 5) - bits))).toByte()
      }

      dst[off] = CHARSET_BYTES[char.toInt()]
      off++

      if (offset > 2) {
        localSrc = localSrc.copyOfRange(1, localSrc.size)
      }

      i += 5
    }
    return off
  }

  public fun decode(s: String): ByteArray {
    return decodeString(s, -1)
  }

  private fun decodeString(s: String, bits: Int): ByteArray {
    val dst = ByteArray(decodedLen(s.length))
    val n = decode(dst, s.toByteArray(), bits)
    return dst.sliceArray(0 until n)
  }

  private fun decodedLen(n: Int): Int {
    return (n + 7) / 8 * 5
  }

  private fun decode(dst: ByteArray, src: ByteArray, bitsVal: Int): Int {
    var bits = bitsVal
    var off = 0
    var localSrc = src.copyOf() // To ensure we don't modify the original array

    while (localSrc.isNotEmpty()) {
      // Decode quantum using the z-base-32 alphabet
      val dbuf = ByteArray(8)

      var j = 0
      while (j < 8) {
        if (localSrc.isEmpty()) {
          break
        }
        val `in` = localSrc[0]
        localSrc = localSrc.copyOfRange(1, localSrc.size)
        dbuf[j] = dec[`in`.toInt()] // Assuming decodeMap is defined elsewhere
        if (dbuf[j] == 0xFF.toByte()) {
          throw Exception("Illegal character: $`in`")
        }
        j++
      }

      // 8x 5-bit source blocks, 5 byte destination quantum
      dst[off] = ((dbuf[0].toInt() shl 3) or (dbuf[1].toInt() shr 2)).toByte()
      dst[off + 1] = ((dbuf[1].toInt() shl 6) or (dbuf[2].toInt() shl 1) or (dbuf[3].toInt() shr 4)).toByte()
      dst[off + 2] = ((dbuf[3].toInt() shl 4) or (dbuf[4].toInt() shr 1)).toByte()
      dst[off + 3] = ((dbuf[4].toInt() shl 7) or (dbuf[5].toInt() shl 2) or (dbuf[6].toInt() shr 3)).toByte()
      dst[off + 4] = ((dbuf[6].toInt() shl 5) or dbuf[7].toInt()).toByte()


      // bits < 0 means as many bits as there are in src
      if (bits < 0) {
        val lookup = intArrayOf(0, 1, 1, 2, 2, 3, 4, 4, 5)
        off += lookup[j]
        continue
      }
      var bitsInBlock = bits
      if (bitsInBlock > 40) {
        bitsInBlock = 40
      }
      off += (bitsInBlock + 7) / 8
      bits -= 40
    }
    return off
  }

}
