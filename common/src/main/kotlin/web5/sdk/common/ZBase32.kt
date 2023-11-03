package web5.sdk.common

import java.io.ByteArrayOutputStream

/**
 * ZBase32 is a variant of Base32 encoding designed to be human-readable and more robust for oral transmission.
 * Reference: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
 */
public object ZBase32 {
  private const val ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
  private const val BITS_PER_BYTE = 8
  private const val BITS_PER_BASE32_CHAR = 5
  private const val MASK_BASE32 = 0x1F // Mask for extracting 5 bits, equivalent to '11111' in binary.
  private const val MASK_BYTE = 0xFF // Mask for byte within an integer, equivalent to '11111111' in binary.
  private const val DECODER_SIZE = 128 // Size of the decoder array based on ASCII range
  private val decoder = IntArray(DECODER_SIZE)

  init {
    // Initialize decoder array with -1 to signify invalid characters for zbase32.
    for (i in decoder.indices) {
      decoder[i] = -1
    }
    // Populate the decoder array with indices of valid zbase32 characters.
    for (i in ALPHABET.indices) {
      decoder[ALPHABET[i].code] = i
    }
  }

  /**
   * Encodes the given byte array to a zbase32-encoded string.
   * @param data the byte array to encode
   * @return a string representing the zbase32-encoded data
   */
  public fun encode(data: ByteArray): String {
    if (data.isEmpty()) {
      return ""
    }

    var buffer = 0
    var bufferLength = 0
    val result = StringBuilder()
    for (b in data) {
      println("byte in: ${b.toUByte()}")
      buffer = (buffer shl BITS_PER_BYTE) + (b.toInt() and MASK_BYTE) // push unsigned byte into buffer
      bufferLength += BITS_PER_BYTE
      println("buffer: $buffer. buffer len: $bufferLength")
      while (bufferLength >= BITS_PER_BASE32_CHAR) {
        val charIndex = (buffer shr bufferLength - BITS_PER_BASE32_CHAR) and MASK_BASE32 // extract 5 bits
        println("pulled ${bufferLength - BITS_PER_BASE32_CHAR}: $charIndex")
        result.append(ALPHABET[charIndex]) // lookup zbase32 character for extracted 5 bits
        bufferLength -= BITS_PER_BASE32_CHAR // decrement 5 bits from current buffer length
      }

      println("remains: $buffer")
    }
    if (bufferLength > 0) {
      val charIndex = (buffer shl BITS_PER_BASE32_CHAR - bufferLength) and MASK_BASE32
      result.append(ALPHABET[charIndex])
    }
    return result.toString()
  }

  /**
   * Decodes a zbase32-encoded string back into its original byte array.
   * @param data the string to decode
   * @return the original byte array
   * @throws IllegalArgumentException if the input contains invalid zbase32 characters
   */
  public fun decode(data: String): ByteArray {
    if (data.isEmpty()) {
      return ByteArray(0)
    }
    var buffer = 0
    var bufferLength = 0
    val result = ByteArrayOutputStream()
    for (c in data) {
      val index = decoder[c.code]
      require(index != -1) { "Invalid zbase32 character: $c" }

      buffer = (buffer shl BITS_PER_BASE32_CHAR) + index
      bufferLength += BITS_PER_BASE32_CHAR
      while (bufferLength >= BITS_PER_BYTE) {
        val b = (buffer shr bufferLength - BITS_PER_BYTE and MASK_BYTE).toByte()
        result.write(b.toInt())
        bufferLength -= BITS_PER_BYTE
      }
    }
    // Handle any remaining bits that may not make up a full byte.
    if (bufferLength > 0) {
      val paddingBits = data.length * BITS_PER_BASE32_CHAR % BITS_PER_BYTE
      if (paddingBits > 0) {
        val paddingBytes = (BITS_PER_BYTE - paddingBits) / BITS_PER_BYTE
        buffer = buffer shl paddingBits
        for (i in 0 until paddingBytes) {
          val b = (buffer shr bufferLength - BITS_PER_BYTE and MASK_BYTE).toByte()
          result.write(b.toInt())
          bufferLength -= BITS_PER_BYTE
        }
      }
    }
    return result.toByteArray()
  }
}