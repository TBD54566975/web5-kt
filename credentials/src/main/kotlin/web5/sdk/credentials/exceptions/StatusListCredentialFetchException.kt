package web5.sdk.credentials.exceptions

/**
 * Status list credential fetch exception.
 *
 * @param message the exception message detailing the error
 * @param cause the underlying exception
 */
public class StatusListCredentialFetchException(message: String, cause: Throwable) : Exception(message, cause)
