package web5.sdk.dids.didcore

import web5.sdk.dids.exceptions.ParserException
import java.util.regex.Pattern

/**
 * DID provides a way to parse and handle Decentralized Identifier (DID) URIs
 * according to the W3C DID Core specification (https://www.w3.org/TR/did-core/).
 *
 * @property uri represents the complete Decentralized Identifier (DID) URI.
 *           Spec: https://www.w3.org/TR/did-core/#did-syntax
 * @property url represents the DID URI + A network location identifier for a specific resource
 * 	         Spec: https://www.w3.org/TR/did-core/#did-url-syntax
 * @property method specifies the DID method in the URI, which indicates the underlying
 * 	         method-specific identifier scheme (e.g., jwk, dht, key, etc.).
 * 	         Spec: https://www.w3.org/TR/did-core/#method-schemes
 * @property id is the method-specific identifier in the DID URI.
 * 	         Spec: https://www.w3.org/TR/did-core/#method-specific-id
 * @property params is a map containing optional parameters present in the DID URI.
 * 	         These parameters are method-specific.
 * 	         Spec: https://www.w3.org/TR/did-core/#did-parameters
 * @property path is an optional path component in the DID URI.
 * 	         Spec: https://www.w3.org/TR/did-core/#path
 * @property query is an optional query component in the DID URI, used to express a request
 * 	         for a specific representation or resource related to the DID.
 * 	         Spec: https://www.w3.org/TR/did-core/#query
 * @property fragment is an optional fragment component in the DID URI, used to reference
 * 	         a specific part of a DID document.
 * 	         Spec: https://www.w3.org/TR/did-core/#fragment
 */
public class DidUri(
  public val uri: String,
  public val url: String,
  public val method: String,
  public val id: String,
  public val params: Map<String, String> = emptyMap(),
  public val path: String? = null,
  public val query: String? = null,
  public val fragment: String? = null
) {
  override fun toString(): String {
    return url
  }

  /**
   * Marshal text into byteArray.
   *
   * @return ByteArray of the DID object
   */
  public fun marshalText(): ByteArray {
    return this.toString().toByteArray(Charsets.UTF_8)
  }

  /**
   * Unmarshal byteArray into a DID.
   *
   * @param byteArray
   * @return DID object
   */
  public fun unmarshalText(byteArray: ByteArray): DidUri {
    return parse(byteArray.toString(Charsets.UTF_8))
  }

  /**
   * Parser object used to Parse a DID URI into a DID object.
   */
  public companion object Parser {
    private const val PCT_ENCODED_PATTERN = """(?:%[0-9a-fA-F]{2})"""
    private const val ID_CHAR_PATTERN = """(?:[a-zA-Z0-9._-]|$PCT_ENCODED_PATTERN)"""
    private const val METHOD_PATTERN = """([a-z0-9]+)"""
    private const val METHOD_ID_PATTERN = """((?:$ID_CHAR_PATTERN*:)*($ID_CHAR_PATTERN+))"""
    private const val PARAM_CHAR_PATTERN = """[a-zA-Z0-9_.:%-]"""
    private const val PARAM_PATTERN = """;$PARAM_CHAR_PATTERN+=$PARAM_CHAR_PATTERN*"""
    private const val PARAMS_PATTERN = """(($PARAM_PATTERN)*)"""
    private const val PATH_PATTERN = """(/[^#?]*)?"""
    private const val QUERY_PATTERN = """(\?[^\#]*)?"""
    private const val FRAGMENT_PATTERN = """(\#.*)?"""
    private val DID_URI_PATTERN = Pattern.compile(
      "^did:$METHOD_PATTERN:$METHOD_ID_PATTERN$PARAMS_PATTERN$PATH_PATTERN$QUERY_PATTERN$FRAGMENT_PATTERN$"
    )

    /**
     * Parse a DID URI into a DID object.
     *
     * @param didUri The DID URI to parse.
     * @return DID object
     */
    public fun parse(didUri: String): DidUri {
      val matcher = DID_URI_PATTERN.matcher(didUri)
      matcher.find()
      if (!matcher.matches()) {
        throw ParserException("Invalid DID URI")
      }

      val method = matcher.group(1)
      val id = matcher.group(2)

      val params = matcher.group(4)
        ?.drop(1)
        ?.split(";")
        ?.mapNotNull {
          it.split("=")
            .takeIf { parts -> parts.size == 2 }
            ?.let { parts -> parts[0] to parts[1] }
        }
        ?.takeIf { it.isNotEmpty() }
        ?.associate { it }
        ?: emptyMap()

      val path = matcher.group(6)?.takeIf { it.isNotEmpty() }
      val query = matcher.group(7)?.drop(1)
      val fragment = matcher.group(8)?.drop(1)

      return DidUri(
        uri = "did:$method:$id",
        url = didUri,
        method = method,
        id = id,
        params = params,
        path = path,
        query = query,
        fragment = fragment
      )
    }
  }
}
