package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve

/**
 * JSON Web Algorithm Curve.
 *
 * @property curveName
 * @property identifier
 * @property oid
 */
public enum class JwaCurve(public val curveName: String, public val identifier: String, public val oid: String?) {
  SECP256K1("secp256k1", "secp256k1", "1.3.132.0.10"),
  Ed25519("Ed25519", "Ed25519", null);

  public companion object {
    /**
     * Parse name of a curve into JwaCurve.
     *
     * @param curveName
     * @return JwaCurve
     */
    public fun parse(curveName: String?): JwaCurve? {
      return if (!curveName.isNullOrEmpty()) {
        when (curveName) {
          SECP256K1.curveName -> SECP256K1
          Ed25519.curveName -> Ed25519
          else -> throw IllegalArgumentException("Unknown curve: $curveName")
        }
      } else {
        null
      }
    }

    /**
     * Convert JwaCurve nimbusds JWK curve.
     *
     * @param curve
     * @return nimbus JWK Curve
     */
    public fun toJwkCurve(curve: JwaCurve): Curve {
      return when (curve) {
        SECP256K1 -> Curve.SECP256K1
        Ed25519 -> Curve.Ed25519
      }
    }
  }
}

/**
 * JSON Web Algorithm enum class.
 */
public enum class Jwa {
  EdDSA,
  ES256K;

  public companion object {
    /**
     * Parse algorithm name into Jwa.
     *
     * @param algorithmName
     * @return Jwa
     */
    public fun parse(algorithmName: String?): Jwa? {
      return if (!algorithmName.isNullOrEmpty()) {
        when (algorithmName) {
          EdDSA.name -> EdDSA
          ES256K.name -> ES256K
          else -> throw IllegalArgumentException("Unknown algorithm: $algorithmName")
        }
      } else {
        null
      }
    }

    /**
     * Convert Jwa to nimbusds JWSAlgorithm.
     *
     * @param algorithm
     * @return JWSAlgorithm
     */
    public fun toJwsAlgorithm(algorithm: Jwa): JWSAlgorithm {
      return when (algorithm) {
        EdDSA -> JWSAlgorithm.EdDSA
        ES256K -> JWSAlgorithm.ES256K
      }
    }
  }
}

/**
 * Algorithm id.
 *
 * @property curveName
 * @property algorithmName
 * @constructor Create empty Algorithm id
 */
public enum class AlgorithmId(public val curveName: String, public val algorithmName: String? = null) {
  secp256k1("secp256k1", "ES256K"),
  Ed25519("Ed25519");

  public companion object {
    /**
     * Parse.
     *
     * @param curve
     * @param algorithm
     * @return
     */
    @JvmOverloads
    public fun parse(curve: JwaCurve?, algorithm: Jwa? = null): AlgorithmId {
      return when (algorithm to curve) {
        Jwa.ES256K to JwaCurve.SECP256K1 -> secp256k1
        Jwa.EdDSA to JwaCurve.Ed25519 -> Ed25519
        null to JwaCurve.Ed25519 -> Ed25519
        else -> throw IllegalArgumentException(
          "Unknown combination of algorithm to curve: " +
            "${algorithm?.name} to ${curve?.name}")
      }
    }
  }
}