package web5.sdk.crypto

import com.nimbusds.jose.jwk.JWK

/**
 * A marker interface to represent options used during signing operations.
 *
 * Implementations of this interface might contain properties and methods that
 * provide specific options or metadata for signature processes in different
 * cryptographic algorithms or signing mechanisms.
 *
 * ### Usage Example:
 * Implement this interface in classes where specific signing options need to
 * be configured and passed to signing methods.
 *
 * ```
 * class MySignOptions : SignOptions {
 *     // Implementation-specific options for signing.
 * }
 * ```
 *
 * @see Signer for usage in signing operations.
 */
public interface SignOptions

/**
 * A marker interface to represent options used during signature verification operations.
 *
 * Implementations of this interface might contain properties and methods that
 * provide specific options or metadata for signature verification processes using
 * different cryptographic algorithms or verification mechanisms.
 *
 * ### Usage Example:
 * Implement this interface in classes where specific verification options need to
 * be configured and passed to verification methods.
 *
 * ```
 * class MyVerifyOptions : VerifyOptions {
 *     // Implementation-specific options for signature verification.
 * }
 * ```
 *
 * @see Signer for usage in signature verification operations.
 */
public interface VerifyOptions

/**
 * An interface defining the contract for signing and verifying signatures on payloads.
 *
 * `Signer` provides a generic approach to:
 * - Creating digital signatures on payloads ([sign])
 * - Verifying digital signatures ([verify])
 *
 * Implementers of this interface should ensure mechanisms provided for
 * signing and verifying respect the cryptographic standards necessary for
 * secure and valid operations.
 *
 * ### Usage Example:
 * ```
 * class MySigner : Signer {
 *     override fun sign(privateKey: JWK, payload: Payload, options: SignOptions?): String {
 *         // Implementation-specific signing logic.
 *     }
 *
 *     override fun verify(publicKey: JWK, jws: String, options: VerifyOptions?) {
 *         // Implementation-specific verification logic.
 *     }
 * }
 * ```
 *
 * Implementers may utilize [SignOptions] and [VerifyOptions] to allow
 * consumers to pass in additional, implementation-specific options
 * to influence the signing and verification processes respectively.
 *
 * @see SignOptions for options during signing.
 * @see VerifyOptions for options during signature verification.
 */
public interface Signer {
  /**
   * Sign a given payload using a private key.
   *
   * @param privateKey The private key in JWK format to be used for signing.
   * @param payload The payload/data to be signed.
   * @param options Additional options to control the signing process.
   * @return A [String] representing the signature.
   */
  public fun sign(privateKey: JWK, payload: ByteArray, options: SignOptions? = null): ByteArray

  /**
   * Verify a signature given a public key, a JSON Web Signature (JWS), and optionally some additional verification options.
   *
   * Implementations should ensure that the verification process adequately checks
   * the validity of the signature against the provided payload, respecting any
   * options provided via [VerifyOptions].
   *
   * @param publicKey The public key in JWK format to be used for verifying the signature.
   * @param jws The JSON Web Signature string to verify.
   * @param options Additional options to control the verification process.
   * @throws SomeExceptionType If verification fails, implementers should throw a specific exception type.
   */
  public fun verify(publicKey: JWK, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions? = null)
}