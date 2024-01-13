package web5.sdk.dids.methods.dht

/**
 * A singleton object for encoding and decoding data in Bencode format.
 */
public object Bencoder {

  /**
   * Encodes a given input into a Bencode formatted string.
   *
   * @param input The data to be encoded.
   * @return The Bencode encoded string.
   * @throws IllegalArgumentException If the input type is not supported.
   */
  public fun encode(input: Any): String = when (input) {
    is String -> "${input.length}:$input"
    is Int, Long -> "i${input}e"
    is List<*> -> input.joinToString(separator = "", prefix = "l", postfix = "e") { encode(it!!) }
    is Map<*, *> -> input.entries.joinToString(
      separator = "",
      prefix = "d",
      postfix = "e"
    ) { (key, value) -> encode(key!!) + encode(value!!) }

    else -> throw IllegalArgumentException("Unsupported type: $input")
  }

  /**
   * Encodes a given input into a Bencode formatted byte array. treats ByteArray
   * input as a string
   *
   * @param input The data to be encoded.
   * @return The Bencode encoded byte array.
   * @throws IllegalArgumentException If the input type is not supported.
   */
  public fun encodeAsBytes(input: Any): ByteArray = when (input) {

    is ByteArray -> {
      "${input.size}:".toByteArray() + input
    }

    else -> encode(input).toByteArray()
  }

  /**
   * Decodes a Bencode formatted string into its original data format.
   *
   * @param input The Bencode formatted string to be decoded.
   * @return A Pair containing the decoded object and the length of the decoded string.
   */
  public fun decode(input: String): Pair<Any, Int> {
    var index = 0
    return when (val currChar = input[index]) {
      'i', 'l', 'd' -> decodeType(input, currChar).also { index += it.second }
      else -> decodeString(input).also { index += it.second }
    }
  }

  // Helper function to delegate decoding based on the type character.
  private fun decodeType(s: String, type: Char): Pair<Any, Int> = when (type) {
    'i' -> decodeInt(s)
    'l' -> decodeList(s)
    'd' -> decodeDict(s)
    else -> decodeString(s)
  }

  // Decodes a Bencode string.
  private fun decodeString(s: String): Pair<String, Int> {
    val lengthPart = s.split(":")[0]
    val digitsInString = lengthPart.length
    val length = lengthPart.toInt()
    return Pair(
      s.substring(digitsInString + 1, digitsInString + 1 + length),
      digitsInString + 1 + length
    )
  }

  // Decodes a Bencode integer.
  private fun decodeInt(s: String): Pair<Int, Int> {
    val eIndex = s.indexOf('e')
    val i = s.substring(1, eIndex).toInt()
    return Pair(i, eIndex + 1)
  }

  // Decodes a Bencode list.
  private fun decodeList(s: String): Pair<List<Any>, Int> {
    val xs = mutableListOf<Any>()
    var index = 1
    while (s[index] != 'e') {
      val (b, i) = decode(s.substring(index))
      xs.add(b)
      index += i
    }
    return Pair(xs, index + 1)
  }

  // Decodes a Bencode dictionary.
  private fun decodeDict(s: String): Pair<Map<Any, Any>, Int> {
    val dict = mutableMapOf<Any, Any>()
    var index = 1
    while (s[index] != 'e') {
      val (key, i1) = decode(s.substring(index))
      val (value, i2) = decode(s.substring(index + i1))
      dict[key] = value
      index += i1 + i2
    }
    return Pair(dict, index + 1)
  }
}
