package web5.sdk.dids.methods.web

import java.util.regex.Pattern

/**
 * Detects if a domain is a localhost domain (non-exhaustive).
 *
 * matches
 *  - localhost
 *  - localhost:<port>
 *  - localhost/path/path
 *  - localhost:<port>/path/path
 *  - 127.0.0.1
 *  - 127.0.0.1:<port>
 *  - 127.0.0.1/path/path
 *  - 127.0.0.1:<port>/path/path
 *
 * examples of what it does not match
 *  - IPv4 addresses other than 127.0.0.1
 *  - <anything>localhost
 *  - localhost<anything>
 *  - localhost.<suffix>
 *  - IPv6 addresses
 */
object LocalHostDomainMatcher {
  private val LOCALHOST_PATTERN = Pattern.compile("^(localhost|127.0.0.1)($|(:\\d+)?(/.*)?)")

  fun isLocalHostDomain(domain: String): Boolean {
    return LOCALHOST_PATTERN.matcher(domain).matches()
  }
}
