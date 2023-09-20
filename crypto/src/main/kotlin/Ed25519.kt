package web5.crypto

import Convert
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters

typealias PrivateKeyJwk = OctetKeyPair
typealias PublicKeyJwk = OctetKeyPair

/**
 * API for generating Ed25519 key pairs, computing public keys from private keys,
 * and signing and verifying messages.
 *
 * **TODO**: include example usage
 */
object Ed25519 {
  fun algorithm(): Algorithm {
    return JWSAlgorithm.EdDSA
  }

  fun curve(): Curve {
    return Curve.Ed25519
  }

  fun keyType(): KeyType {
    return KeyType.OKP
  }

  fun generatePrivateKey(): ByteArray {
    val privateKeyJwk = generatePrivateKeyJwk()
    return privateKeyJwk.decodedD
  }

  fun getPublicKey(privateKeyBytes: ByteArray): ByteArray {
    val privateKeyParameters = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
    return privateKeyParameters.generatePublicKey().encoded
  }

  fun generatePrivateKeyJwk(): PrivateKeyJwk {
    return OctetKeyPairGenerator(Curve.Ed25519)
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): PublicKeyJwk {
    return privateKeyJwk.toPublicJWK()
  }

  fun privateKeyToJwk(privateKeyBytes: ByteArray): PrivateKeyJwk {
    val publicKeyBytes = getPublicKey(privateKeyBytes)

    val base64UrlEncodedPrivateKey = Convert(privateKeyBytes).toBase64Url(padding = false)
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(curve(), Base64URL(base64UrlEncodedPublicKey))
      .keyIDFromThumbprint()
      .d(Base64URL(base64UrlEncodedPrivateKey))
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(algorithm())
      .build()
  }
}