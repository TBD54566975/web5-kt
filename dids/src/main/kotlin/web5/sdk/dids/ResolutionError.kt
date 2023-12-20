package web5.sdk.dids

/**
 * Represents a DID resolution error as described in https://w3c-ccg.github.io/did-resolution/#errors.
 */
public enum class ResolutionError(public val value: String) {
  METHOD_NOT_SUPPORTED("methodNotSupported"),
  NOT_FOUND("notFound"),
  INVALID_DID("invalidDid"),
}
