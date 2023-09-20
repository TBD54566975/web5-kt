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
}