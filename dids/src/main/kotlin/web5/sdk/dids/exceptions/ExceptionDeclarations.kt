package web5.sdk.dids.exceptions

/**
 * Pkarr record response exception.
 *
 * @param message the exception message detailing the error
 */
public class PkarrRecordResponseException(message: String) : RuntimeException(message)

/**
 * Invalid method name exception.
 *
 * @param message the exception message detailing the error
 */
public class InvalidMethodNameException(message: String) : RuntimeException(message)

/**
 * Invalid identifier size exception.
 *
 * @param message the exception message detailing the error
 */
public class InvalidIdentifierSizeException(message: String) : RuntimeException(message)

/**
 * Pkarr Record not found exception.
 */
public class PkarrRecordNotFoundException : RuntimeException()

/**
 * Invalid identifier exception.
 *
 * @param message the exception message detailing the error
 * @param cause the exception cause
 */
public class InvalidIdentifierException(message: String, cause: Throwable) : RuntimeException(message, cause)

/**
 * Did resolution exception.
 *
 * @param message the exception message detailing the error
 */
public class DidResolutionException(message: String) : RuntimeException(message)

/**
 * Represents an HTTP response where the status code is outside the range considered success.
 */
public class InvalidStatusException(public val statusCode: Int, msg: String) : RuntimeException(msg)
