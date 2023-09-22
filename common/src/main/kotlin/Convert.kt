package web5.common

import java.util.Base64

public val B64URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder()
public val B64URL_DECODER: Base64.Decoder = Base64.getUrlDecoder()

/**
 * TODO: implement https://github.com/TBD54566975/web5-js/blob/main/packages/common/src/convert.ts
 */
public class Convert<T>(public val value: T, public val kind: String? = null) {
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

  public fun toByteArray(): ByteArray {
    return when (this.value) {
      is ByteArray -> this.value
      is String -> {
        return when (this.kind) {
          "base58btc" -> Base58Btc.decode(this.value)
          "base64url" -> B64URL_DECODER.decode(this.value)
          null -> this.value.toByteArray()
          else -> handleNotSupported()
        }
      }

      else -> handleNotSupported()
    }
  }

  private fun handleNotSupported(): Nothing {
    value?.let {
      throw Exception("converting from ${it::class} not supported")
    } ?: throw NullPointerException("value is null")
  }
}

public fun Convert<String>.asBase64Url(): Convert<String> {
  return Convert(this.value, "base64url")
}