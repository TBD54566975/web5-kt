package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import web5.sdk.common.Varint
import web5.sdk.crypto.Secp256k1.privMultiCodec
import web5.sdk.crypto.Secp256k1.pubMulticodec
import java.math.BigInteger


/**
 * A cryptographic object responsible for key generation, signature creation, and signature verification
 * utilizing the SECP256K1 elliptic curve, widely used for Bitcoin and Ethereum transactions.
 *
 * The object uses the Nimbus JOSE+JWT library and implements the [KeyGenerator] and [Signer] interfaces,
 * providing specific implementation details for SECP256K1.
 *
 * ### Key Points:
 * - Utilizes the ES256K algorithm for signing JWTs.
 * - Utilizes BouncyCastle as the underlying security provider.
 * - Public and private keys can be encoded with [pubMulticodec] and [privMultiCodec] respectively.
 *
 * ### Example Usage:
 * ```
 * val privateKey = Secp256k1.generatePrivateKey()
 * val publicKey = Secp256k1.getPublicKey(privateKey)
 * ```
 *
 * ### Key Generation and Management:
 * - `generatePrivateKey`: Generates a private key for the SECP256K1 curve.
 * - `getPublicKey`: Derives the corresponding public key from a private key.
 *
 * ### Signing and Verification:
 * - `sign`: Generates a digital signature.
 * - `verify`: Verifies a digital signature.
 *
 * **Note:** The actual byte conversion and cryptographic functions are marked as `TODO`
 * and need to be implemented as per your requirements.
 *
 * @see KeyGenerator for generating key details.
 * @see Signer for handling signing operations.
 */
public object Secp256k1 : KeyGenerator, Signer {
  override val algorithm: Algorithm = JWSAlgorithm.ES256K
  override val keyType: KeyType = KeyType.EC

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L92) */
  public val pubMulticodec: ByteArray = Varint.encode(0xe7)

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L169) */
  public val privMultiCodec: ByteArray = Varint.encode(0x1301)

  /**
   * Generates a private key using the SECP256K1 curve and ES256K algorithm.
   *
   * The generated key will have its key ID derived from the thumbprint and will
   * be intended for signature use.
   *
   * @param options Options for key generation (currently unused, provided for possible future expansion).
   * @return A JWK representing the generated private key.
   */
  override fun generatePrivateKey(options: KeyGenOptions?): JWK {
    return ECKeyGenerator(Curve.SECP256K1)
      .algorithm(JWSAlgorithm.ES256K)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  override fun getPublicKey(privateKey: JWK): JWK {
    validateKey(privateKey)

    return privateKey.toECKey().toPublicJWK()
  }

  override fun privateKeyToBytes(privateKey: JWK): ByteArray {
    validateKey(privateKey)

    return privateKey.toECKey().d.decode()
  }

  override fun publicKeyToBytes(publicKey: JWK): ByteArray {
    TODO("Not yet implemented")
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK {
    val spec = ECNamedCurveTable.getParameterSpec("secp256k1")
    var pointQ: ECPoint = spec.g.multiply(BigInteger(1, privateKeyBytes))

    pointQ = pointQ.normalize()
    val rawX = pointQ.rawXCoord.encoded
    val rawY = pointQ.rawYCoord.encoded

    return ECKey.Builder(Curve.SECP256K1, Base64URL.encode(rawX), Base64URL.encode(rawY))
      .algorithm(JWSAlgorithm.ES256K)
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK {
    TODO("Not yet implemented")
  }

  override fun sign(privateKey: JWK, payload: Payload, options: SignOptions?): String {
    TODO("Not yet implemented")
  }

  override fun verify(publicKey: JWK, jws: String, options: VerifyOptions?) {
    TODO("Not yet implemented")
  }

  public fun validateKey(key: JWK) {
    require(key is OctetKeyPair) { "private key must be an Octet Key Pair (kty: OKP)" }
    require(key.keyType == keyType) { "private key key type must be OKP" }
  }

}