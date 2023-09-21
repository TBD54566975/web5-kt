package web5.crypto

import web5.common.Convert
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters

/**
 * API for generating Ed25519 key pairs, computing public keys from private keys,
 * and signing and verifying messages.
 *
 * **TODO**: include example usage
 */

object Ed25519 : CryptoPrimitive<OctetKeyPair> {
  override val algorithm: Algorithm = JWSAlgorithm.EdDSA
  override val curve: Curve = Curve.Ed25519
  override val keyType: KeyType = KeyType.OKP
  override val keyUse: KeyUse = KeyUse.SIGNATURE

  override fun generatePrivateKey(): ByteArray {
    val privateKeyJwk = generatePrivateKeyJwk()
    return privateKeyJwk.decodedD
  }

  override fun generatePrivateKey(options: GenerateOptions): ByteArray {
    throw Exception("Ed25519 has no options when generating a private key")
  }

  override fun getPublicKey(privateKeyBytes: ByteArray): ByteArray {
    val privateKeyParameters = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
    return privateKeyParameters.generatePublicKey().encoded
  }

  override fun generatePrivateKeyJwk(): OctetKeyPair {
    return OctetKeyPairGenerator(curve)
      .keyIDFromThumbprint(true)
      .keyUse(keyUse)
      .generate()
  }

  override fun generatePrivateKeyJwk(options: GenerateOptions): OctetKeyPair {
    throw Exception("Ed25519 has no options when generating a private key")
  }

  override fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): JWK {
    return privateKeyJwk.toPublicJWK()
  }

  override fun privateKeyToJwk(privateKeyBytes: ByteArray): OctetKeyPair {
    val publicKeyBytes = getPublicKey(privateKeyBytes)

    val base64UrlEncodedPrivateKey = Convert(privateKeyBytes).toBase64Url(padding = false)
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(curve, Base64URL(base64UrlEncodedPublicKey))
      .keyIDFromThumbprint()
      .d(Base64URL(base64UrlEncodedPrivateKey))
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(algorithm)
      .build()
  }

  override fun publicKeyToJwk(publicKeyBytes: ByteArray): JWK {
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(curve, Base64URL(base64UrlEncodedPublicKey))
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(algorithm)
      .build()

  }
}