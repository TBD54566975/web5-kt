import java.util.Base64

public val B64URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder()
public val B64URL_DECODER: Base64.Decoder = Base64.getUrlDecoder()

// TODO: implement https://github.com/TBD54566975/web5-js/blob/main/packages/common/src/convert.ts
/**
 * A utility class for converting values to various formats, including Base64 and Base58BTC.
 *
 * @param T The type of the value to be converted.
 * @param value The value to be converted.
 * @param kind An optional string representing the kind of conversion.
 */
public class Convert<T>(public val value: T, public val kind: String? = null) {
  /**
   * Converts the value to a Base64 URL-encoded string.
   *
   * @param padding Specifies whether to include padding characters in the encoded string.
   * @return The Base64 URL-encoded string.
   */
  public fun toBase64Url(padding: Boolean = true): String {
    val encoder = if (padding) B64URL_ENCODER else B64URL_ENCODER.withoutPadding()

    return when (this.value) {
      is ByteArray -> encoder.encodeToString(this.value)
      is String -> {
        return when (this.kind) {
          "base64url" -> return this.value
          null -> encoder.encodeToString(this.toByteArray())
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the value to a Base58BTC-encoded string.
   *
   * @return The Base58BTC-encoded string.
   */
  public fun toBase58Btc(): String {
    return when (this.value) {
      is ByteArray -> Base58Btc.encode(this.value)
      is String -> {
        return when (this.kind) {
          "base58btc" -> this.value
          "base64url" -> Base58Btc.encode(B64URL_DECODER.decode(this.value))
          null -> Base58Btc.encode(this.toByteArray())
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the value to a string.
   *
   * @return The string representation of the value.
   */
  public fun toStr(): String {
    return when (this.value) {
      is ByteArray -> String(this.value)
      is String -> {
        return when (this.kind) {
          "base64url" -> String(B64URL_DECODER.decode(this.value))
          null -> this.value
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the value to a byte array.
   *
   * @return The byte array representation of the value.
   */
  public fun toByteArray(): ByteArray {
    return when (this.value) {
      is ByteArray -> this.value
      is String -> this.value.toByteArray()
      else -> handleNotSupported()
    }
  }

  private fun handleNotSupported(): Nothing {
    value?.let {
      throw Exception("converting from ${it::class} not supported")
    } ?: throw NullPointerException("value is null")
  }
}

/**
 * Converts a string value to a Base64 URL-encoded format.
 *
 * @return A Convert object representing the conversion.
 */
public fun Convert<String>.asBase64Url(): Convert<String> {
  return Convert(this.value, "base64url")
}