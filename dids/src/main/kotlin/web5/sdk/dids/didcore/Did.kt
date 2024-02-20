package web5.sdk.dids.didcore

import java.util.regex.Pattern

public class DID(
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

  public fun marshalText(): ByteArray {
    return this.toString().toByteArray(Charsets.UTF_8)
  }

  public fun unmarshalText(text: ByteArray): DID {
    return parse(text.toString(Charsets.UTF_8))
  }

  public companion object Parser {
    private val pctEncodedPattern = """(?:%[0-9a-fA-F]{2})"""
    private val idCharPattern = """(?:[a-zA-Z0-9._-]|$pctEncodedPattern)"""
    private val methodPattern = """([a-z0-9]+)"""
    private val methodIdPattern = """((?:$idCharPattern*:)*($idCharPattern+))"""
    private val paramCharPattern = """[a-zA-Z0-9_.:%-]"""
    private val paramPattern = """;$paramCharPattern+=$paramCharPattern*"""
    private val paramsPattern = """(($paramPattern)*)"""
    private val pathPattern = """/[^#?]*"""
    private val queryPattern = """(\?[^#]*)?"""
    private val fragmentPattern = """(\#.*)?"""
    private val didUriPattern =
      Pattern.compile("""^did:$methodPattern:$methodIdPattern$paramsPattern$pathPattern$queryPattern$fragmentPattern$""")

    public fun parse(input: String): DID {
      val matcher = didUriPattern.matcher(input)
      if (!matcher.matches()) {
        throw IllegalArgumentException("Invalid DID URI")
      }

      val method = matcher.group(1)
      val id = matcher.group(2)
      val params = matcher.group(4)
        ?.drop(1)
        ?.split(";")
        ?.associate {
          val (key, value) = it.split("=")
          key to value
        } ?: emptyMap()

      val path = matcher.group(6)?.takeIf { it.isNotEmpty() }
      val query = matcher.group(7)?.drop(1)
      val fragment = matcher.group(8)?.drop(1)

      return DID(
        uri = "did:$method:$id",
        url = input,
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
