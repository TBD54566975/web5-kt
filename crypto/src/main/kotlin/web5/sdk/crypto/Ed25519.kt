package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import web5.sdk.common.Convert
import web5.sdk.common.Varint

/**
 * API for generating Ed25519 key pairs, computing public keys from private keys,
 * and signing and verifying messages.
 *
 * **TODO**: include example usage
 */

public object Ed25519 : KeyGenerator, Signer {
  override val algorithm: Algorithm = JWSAlgorithm.EdDSA
  override val keyType: KeyType = KeyType.OKP

  public val pubMulticodec: ByteArray = Varint.encode(0xed)
  public val privMultiCodec: ByteArray = Varint.encode(0x1300)

  override fun generatePrivateKey(options: KeyGenOptions?): JWK {
    return OctetKeyPairGenerator(Curve.Ed25519)
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
      .toOctetKeyPair()
  }

  override fun getPublicKey(privateKey: JWK): JWK {
    require(privateKey is OctetKeyPair) { "private key must be an Octet Key Pair (kty: OKP)" }

    return privateKey.toOctetKeyPair().toPublicJWK()
  }

  override fun privateKeyToBytes(privateKey: JWK): ByteArray {
    validateKey(privateKey)

    return privateKey.toOctetKeyPair().decodedD
  }

  override fun publicKeyToBytes(publicKey: JWK): ByteArray {
    validateKey(publicKey)

    return publicKey.toOctetKeyPair().decodedX
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK {
    val privateKeyParameters = Ed25519PrivateKeyParameters(privateKeyBytes, 0)
    val publicKeyBytes = privateKeyParameters.generatePublicKey().encoded

    val base64UrlEncodedPrivateKey = Convert(privateKeyBytes).toBase64Url(padding = false)
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(Curve.Ed25519, Base64URL(base64UrlEncodedPublicKey))
      .algorithm(algorithm)
      .keyIDFromThumbprint()
      .d(Base64URL(base64UrlEncodedPrivateKey))
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK {
    val base64UrlEncodedPublicKey = Convert(publicKeyBytes).toBase64Url(padding = false)

    return OctetKeyPair.Builder(Curve.Ed25519, Base64URL(base64UrlEncodedPublicKey))
      .algorithm(algorithm)
      .keyIDFromThumbprint()
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  override fun sign(privateKey: JWK, payload: Payload, options: SignOptions?): String {
    val jwsHeader = JWSHeader.Builder(JWSAlgorithm.EdDSA)
      .keyID(privateKey.keyID)
      .build()

    val jws = JWSObject(jwsHeader, payload)
    val signer = Ed25519Signer(privateKey as OctetKeyPair)
    jws.sign(signer)

    return jws.serialize()
  }

  override fun verify(options: VerifyOptions?) {
    TODO("Not yet implemented")
  }

  public fun validateKey(key: JWK) {
    require(key is OctetKeyPair) { "private key must be an Octet Key Pair (kty: OKP)" }
    require(key.keyType == keyType) { "private key key type must be OKP" }
  }
}