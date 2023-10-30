package web5.sdk.common

/**
 * Represents an HTTP response where the status code is outside the range considered success.
 */
public class InvalidStatusException(public val statusCode: Int, msg: String) : RuntimeException(msg)