package web5.sdk.common

import java.util.Base64

/**
 * A Base64 URL encoder for encoding data into Base64 URL-safe format.
 *
 * This encoder is used to encode binary data into a URL-safe Base64 representation.
 * Base64 URL encoding replaces characters like '+' and '/' with '-' and '_', respectively,
 * making the resulting string safe for use in URLs.
 */
public val B64URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder()

/**
 * Enumeration of supported encoding formats.
 */
public enum class EncodingFormat {
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
 * A utility class [Convert] to facilitate various conversions including Base64 and Base58BTC.
 *
 * @param T The type of the value to be converted.
 * @param value The actual value to be converted.
 * @param kind Specifies the kind of conversion (optional parameter).
 *
 * Note: Usage of this class should ensure that the type [T] and [kind] are compatible with
 * the conversion methods, as certain methods may not support all data types or kinds
 *
 * Example Usage:
 * ```
 * // Example 1: Convert a ByteArray to a Base64Url encoded string without padding
 * val byteArray = byteArrayOf(1, 2, 3)
 * val base64Url = Convert(byteArray).toBase64Url(padding = false)
 * println(base64Url)  // Output should be a Base64Url encoded string without padding
 *
 * // Example 2: Convert a Base64Url encoded string to a ByteArray
 * val base64Str = "AQID"
 * val originalByteArray = Convert(base64Str, EncodingFormat.Base64Url).toByteArray()
 *
 * // Example 3: Convert a ByteArray to a Base58Btc encoded string
 * val byteArray = byteArrayOf(1, 2, 3)
 * val base58BtcStr = Convert(byteArray).toBase58Btc()
 * println(base58BtcStr)  // Output should be a Base58Btc encoded string
 *
 * // Example 4: Convert a Base64Url encoded string to a regular string
 * val base64UrlStr = "SGVsbG8gd29ybGQ="
 * val decodedStr = Convert(base64UrlStr, EncodingFormat.Base64Url).toStr()
 * println(decodedStr)  // Output should be: "Hello world"
 * ```
 */
public class Convert<T>(private val value: T, private val kind: EncodingFormat? = null) {
  /**
   * Converts the [value] to a Base64Url-encoded string.
   *
   * @param padding Determines whether the resulting Base64 string should be padded or not. Default is true.
   * @return The Base64Url-encoded string.
   *
   * Note: If the value type is unsupported for this conversion, the method will throw an exception.
   */
  public fun toBase64Url(padding: Boolean = true): String {
    val encoder = if (padding) B64URL_ENCODER else B64URL_ENCODER.withoutPadding()

    return when (this.value) {
      is ByteArray -> encoder.encodeToString(this.value)
      is String -> {
        return when (this.kind) {
          EncodingFormat.Base64Url -> this.value
          null -> encoder.encodeToString(this.toByteArray())
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the [value] to a Base58BTC-encoded string.
   *
   * @return The Base58BTC-encoded string.
   *
   * Note: If the value type or kind is unsupported for this conversion, the method will throw an exception.
   */
  public fun toBase58Btc(): String {
    return when (this.value) {
      is ByteArray -> Base58Btc.encode(this.value)
      is String -> {
        return when (this.kind) {
          EncodingFormat.Base58Btc -> this.value
          EncodingFormat.Base64Url -> Base58Btc.encode(B64URL_DECODER.decode(this.value))
          null -> Base58Btc.encode(this.toByteArray())
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the [value] to a string representation.
   *
   * @return The string representation of the [value].
   *
   * Note: If the value type or kind is unsupported for this conversion, the method will throw an exception.
   */
  public fun toStr(): String {
    return when (this.value) {
      is ByteArray -> String(this.value)
      is String -> {
        return when (this.kind) {
          EncodingFormat.Base64Url -> String(B64URL_DECODER.decode(this.value))
          null -> this.value
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * Converts the [value] to a byte array representation.
   *
   * @return The byte array representation of the [value].
   *
   * Note: If the value type or kind is unsupported for this conversion, the method will throw an exception.
   */
  public fun toByteArray(): ByteArray {
    return when (this.value) {
      is ByteArray -> this.value
      is String -> {
        return when (this.kind) {
          EncodingFormat.Base58Btc -> Base58Btc.decode(this.value)
          EncodingFormat.Base64Url -> B64URL_DECODER.decode(this.value)
          null -> this.value.toByteArray()
        }
      }

      else -> handleNotSupported()
    }
  }

  /**
   * A private utility function to handle unsupported conversion scenarios.
   *
   * This function throws:
   * - [UnsupportedOperationException] when the [value]'s type is not supported for the conversion,
   * - [NullPointerException] when the [value] is null.
   */
  private fun handleNotSupported(): Nothing {
    value?.let {
      throw UnsupportedOperationException("converting from ${it::class} not supported")
    } ?: throw NullPointerException("value is null")
  }
}