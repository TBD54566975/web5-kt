package web5.sdk.crypto

/**
 * Represents a cryptographic curve.
 */
public enum class Curve(public val ianaName: String) {
  SECP256K1("secp256k1"),
  Ed25519("Ed25519");

  internal fun toNimbusdsCurve(): com.nimbusds.jose.jwk.Curve? {
    return when (this) {
      SECP256K1 -> com.nimbusds.jose.jwk.Curve.SECP256K1
      Ed25519 -> com.nimbusds.jose.jwk.Curve.Ed25519
    }
  }

  public companion object {
    private val ianaNames = Curve.entries.associateBy { it.ianaName }

    /**
     * Returns a [Curve] object given it's [ianaName]. The [ianaName] is how the curve was registered in the IANA table
     * available at https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve. When there is no Curve for
     * the given [ianaName], null is returned.
     */
    public fun parse(ianaName: String): Curve? {
      return ianaNames[ianaName]
    }
  }

}
