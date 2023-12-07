package web5.sdk.credentials


/**
 * Bitstring expansion exception.
 *
 * @param cause the underlying exception
 * @param message the exception message detailing the error
 */
public class BitstringExpansionException(cause: Throwable, message: String? = null) : RuntimeException(message, cause)

/**
 * Presentation exchange exception.
 *
 * @param message the exception message
 */
public class PresentationExchangeException(message: String) : RuntimeException(message)

/**
 * Status list credential create exception.
 *
 * @param cause the underlying exception
 * @param message the exception message detailing the error
 */
public class StatusListCredentialCreateException(cause: Throwable, message: String? = null) : RuntimeException(message, cause)

/**
 * Status list credential fetch exception.
 *
 * @param cause the underlying exception
 * @param message the exception message detailing the error
 */
public class StatusListCredentialFetchException(cause: Throwable, message: String? = null) : RuntimeException(message, cause)

/**
 * Verifiable credential parse exception.
 *
 * @param cause the underlying exception
 * @param message the exception message detailing the error
 */
public class VerifiableCredentialParseException(cause: Throwable, message: String? = null) : RuntimeException(message, cause)
