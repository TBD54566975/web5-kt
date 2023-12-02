package web5.sdk.credentials.exceptions

/**
 * Verifiable credential parse exception.
 *
 * @param message the exception message detailing the error
 * @param cause the underlying exception
 */
public class VerifiableCredentialParseException(message: String, cause: Throwable) : Exception(message, cause)
