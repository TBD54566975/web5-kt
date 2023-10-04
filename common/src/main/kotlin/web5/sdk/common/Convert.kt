package web5.sdk.common

import java.lang.UnsupportedOperationException
import java.util.Base64

/**
 * A Base64 URL encoder for encoding data into Base64 URL-safe format.
 *
 * This encoder is used to encode binary data into a URL-safe Base64 representation.
 * Base64 URL encoding replaces characters like '+' and '/' with '-' and '_', respectively,
 * making the resulting string safe for use in URLs.
 */
public val B64URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder()

public enum class StringKind {
  Base64Url,
  Base58Btc
}

/**
 * A Base64 URL decoder for decoding data from Base64 URL-safe format.
 *
 * This decoder is used to decode Base64 URL-safe encoded strings back into their original binary data.
 * It can handle strings that were encoded using the Base64 URL-safe encoding scheme, which is designed
 * for safe inclusion in URLs without requiring additional URL encoding.
 */
public val B64URL_DECODER: Base64.Decoder = Base64.getUrlDecoder()

// TODO: implement https://github.com/TBD54566975/web5-js/blob/main/packages/common/src/convert.ts
/**
 * A utility class for converting values to various formats, including Base64 and Base58BTC.
 *
 * @param T The type of the value to be converted.
 * @param value The value to be converted.
 * @param kind An optional string representing the kind of conversion.
 */
public class Convert<T>(private val value: T, private val kind: StringKind? = null) {
  public fun toBase64Url(padding: Boolean = true): String {
    val encoder = if (padding) B64URL_ENCODER else B64URL_ENCODER.withoutPadding()

    return when (this.value) {
      is ByteArray -> encoder.encodeToString(this.value)
      is String -> {
        return when (this.kind) {
          StringKind.Base64Url -> this.value
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
          StringKind.Base58Btc -> this.value
          StringKind.Base64Url -> Base58Btc.encode(B64URL_DECODER.decode(this.value))
          null -> Base58Btc.encode(this.toByteArray())
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
          StringKind.Base64Url -> String(B64URL_DECODER.decode(this.value))
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
      is String -> {
        return when (this.kind) {
          StringKind.Base58Btc -> Base58Btc.decode(this.value)
          StringKind.Base64Url -> B64URL_DECODER.decode(this.value)
          null -> this.value.toByteArray()
        }
      }

      else -> handleNotSupported()
    }
  }

  private fun handleNotSupported(): Nothing {
    value?.let {
      throw UnsupportedOperationException("converting from ${it::class} not supported")
    } ?: throw NullPointerException("value is null")
  }
}