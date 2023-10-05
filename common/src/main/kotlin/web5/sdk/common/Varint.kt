package web5.sdk.common

/**
 * Object Varint contains utility functions to encode and decode integers using variable-length quantity (Varint).
 * Varint is a method of serializing integers using one or more bytes; smaller integers use fewer bytes.
 * Used by Multicodec (which is used for DidKey)
 */
public object Varint {
  // represents the maximum number of bytes a Varint can be.
  private const val MAX_VARINT_SIZE = 10

  // represents the number of bits in each byte that store the value in Varint encoding.
  private const val VALUE_BITS_PER_BYTE = 7

  // used to check if more bytes are there to read.
  private const val CONTINUE_MASK = 0x80

  // used to get value bits
  private const val VALUE_MASK = 0x7F

  //  the maximum number of bits that can be shifted.
  private const val MAX_SHIFT = 35

  // used in the encoding process to check the continuation condition.
  private const val BYTE_MASK = 0xFFFFFF80.toInt()

  /**
   * Encodes the given integer [inp] into a ByteArray using Varint encoding.
   * The function supports encoding of Integers to Varint byte arrays, which are more efficient in representing
   * smaller numbers using fewer bytes.
   *
   * @param inp The integer to be encoded.
   * @return The ByteArray representing [inp] in Varint format.
   */
  public fun encode(inp: Int): ByteArray {
    var value = inp
    val byteArrayList = ByteArray(MAX_VARINT_SIZE)
    var i = 0
    while (value and BYTE_MASK != 0) {
      byteArrayList[i++] = ((value and VALUE_MASK) or CONTINUE_MASK).toByte()
      value = value ushr VALUE_BITS_PER_BYTE
    }
    byteArrayList[i] = (value and VALUE_MASK).toByte()
    val out = ByteArray(i + 1)
    while (i >= 0) {
      out[i] = byteArrayList[i]
      i--
    }

    return out
  }

  /**
   * Decodes the given ByteArray [input] from Varint format to a Pair of Integers.
   * The function extracts the integer represented by the Varint and the number of bytes read to decode the integer.
   *
   * @param input The ByteArray to be decoded, representing an integer in Varint format.
   * @return A Pair where the first element is the decoded integer and the second element is the number of bytes read
   * from [input] to decode the integer.
   * @throws IllegalArgumentException If the Varint is malformed and too long.
   */
  public fun decode(input: ByteArray): Pair<Int, Int> {
    var value = 0
    var i = 0
    var bytesRead = 0
    var b: Int

    while (true) {
      b = input[bytesRead].toInt()
      bytesRead++

      if (b and CONTINUE_MASK == 0) break

      value = value or (b and VALUE_MASK shl i)
      i += VALUE_BITS_PER_BYTE
      require(i <= MAX_SHIFT) { "Variable length quantity is too long" }
    }

    value = value or (b shl i)

    return Pair(value, bytesRead)
  }
}
