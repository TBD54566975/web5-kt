package web5.sdk.common

import java.lang.UnsupportedOperationException
import java.util.Base64

public val B64URL_ENCODER: Base64.Encoder = Base64.getUrlEncoder()
public val B64URL_DECODER: Base64.Decoder = Base64.getUrlDecoder()

public enum class StringKind {
  Base64Url,
  Base58Btc
}

/**
 * TODO: implement https://github.com/TBD54566975/web5-js/blob/main/packages/common/src/convert.ts
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