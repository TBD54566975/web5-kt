package web5.sdk.crypto

import com.nimbusds.jose.Payload
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

public interface VerifyOptions

public interface Signer {
  /**
   * Sign a given payload using a private key and optionally some additional options.
   *
   * @param privateKey The private key in JWK format to be used for signing.
   * @param payload The payload/data to be signed.
   * @param options Additional options to control the signing process.
   * @return A [String] representing the signature.
   */
  public fun sign(privateKey: JWK, payload: Payload, options: SignOptions? = null): String

  /**
   * Verify a signature given some verification options.
   *
   * @param options Options guiding the verification process.
   */
  public fun verify(publicKey: JWK, jws: String, options: VerifyOptions? = null)
}