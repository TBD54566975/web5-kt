package web5.sdk.crypto

import com.nimbusds.jose.jwk.JWK
import java.security.SignatureException

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
   * This function takes a payload and a private key in JWK (JSON Web Key) format,
   * and returns a signature as a byte array. Additional options for the signing
   * process can be provided via the `options` parameter.
   *
   * @param privateKey The private key in JWK format to be used for signing.
   *                   Must not be null.
   * @param payload The payload/data to be signed. Must not be null.
   * @param options Optional parameter containing additional options to control
   *                the signing process. Default is null.
   * @return A [ByteArray] representing the signature.
   */
  public fun sign(privateKey: JWK, payload: ByteArray, options: SignOptions? = null): ByteArray

  /**
   * Verify the signature of a given payload using a public key.
   *
   * This function attempts to verify the signature of a provided payload using a public key,
   * supplied in JWK (JSON Web Key) format, and a signature. The verification process checks
   * the validity of the signature against the provided payload, respecting any optional
   * verification options provided via [VerifyOptions].
   *
   * @param publicKey The public key in JWK format used for verifying the signature.
   *                  Must not be null.
   * @param signedPayload The original payload/data that was signed, to be verified
   *                      against its signature. Must not be null.
   * @param signature The signature to be verified against the payload and public key.
   *                  Must not be null.
   * @param options Optional parameter containing additional options to control the
   *                verification process. Default is null.
   *
   * @throws [SignatureException] if the verification fails.
   */
  public fun verify(publicKey: JWK, signedPayload: ByteArray, signature: ByteArray, options: VerifyOptions? = null)
}