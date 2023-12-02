package web5.sdk.crypto

/**
 * The supported JSON Web Signature algorithms.
 */
public enum class JWSAlgorithm {
  /** ECDSA using secp256k1 curve and SHA-256. */
  ES256K,

  /** Edwards-curve Digital Signature Algorithm. */
  EdDSA;

  internal fun toJwsAlgorithm(): com.nimbusds.jose.JWSAlgorithm {
    return when (this) {
      ES256K -> com.nimbusds.jose.JWSAlgorithm.ES256K
      EdDSA -> com.nimbusds.jose.JWSAlgorithm.EdDSA
    }
  }
}
