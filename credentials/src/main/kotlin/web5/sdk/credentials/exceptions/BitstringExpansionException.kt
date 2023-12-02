package web5.sdk.credentials.exceptions

/**
 * Bitstring expansion exception.
 *
 * @param message the exception message detailing the error
 * @param cause the underlying exception
 */
public class BitstringExpansionException(message: String, cause: Throwable) : RuntimeException(message, cause)
