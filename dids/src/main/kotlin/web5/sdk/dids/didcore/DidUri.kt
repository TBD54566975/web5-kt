package web5.sdk.dids.didcore

import java.util.regex.Pattern

public class DidUri(
  public val uri: String,
  public val method: String,
  public val id: String,
  public val params: Map<String, String>? = null,
  public val path: String? = null,
  public val query: String? = null,
  public val fragment: String? = null
) {
  public companion object {
    private val pctEncodedPattern = "(?:%[0-9a-fA-F]{2})"
    private val idCharPattern = "(?:[a-zA-Z0-9._-]|$pctEncodedPattern)"
    private val methodPattern = "([a-z0-9]+)"
    private val methodIdPattern = "(($idCharPattern*:)*($idCharPattern+))"
    private val paramCharPattern = "[a-zA-Z0-9_.:%-]"
    private val paramPattern = ";$paramCharPattern+=$paramCharPattern*"
    private val paramsPattern = "(($paramPattern)*)"
    private val pathPattern = "(/[^#?]*)?"
    private val queryPattern = "(\\?[^\\#]*)?"
    private val fragmentPattern = "(\\#.*)?"
    private val didUriPattern = Pattern.compile(
      "^did:$methodPattern:$methodIdPattern$paramsPattern$pathPattern$queryPattern$fragmentPattern\$"
    )

    public fun parse(input: String): DidUri {
      val matcher = didUriPattern.matcher(input)

      if (!matcher.find()) {
        throw IllegalArgumentException("Invalid DID URI")
      }

      val methodMatch = matcher.group(1)!!
      val idMatch = matcher.group(2)!!
      val paramsMatch = matcher.group(4)
      val pathMatch = matcher.group(6)
      val queryMatch = matcher.group(7)
      val fragmentMatch = matcher.group(8)

      val parsedParams = paramsMatch?.substring(1)?.split(";")
        ?.associate {
          val (key, value) = it.split("=")
          key to value
        }

      return DidUri(
        uri = "did:$methodMatch:$idMatch",
        method = methodMatch,
        id = idMatch,
        params = parsedParams,
        path = pathMatch,
        query = queryMatch?.substring(1),
        fragment = fragmentMatch?.substring(1)
      )
    }
  }
}