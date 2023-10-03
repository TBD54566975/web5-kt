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
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import web5.sdk.common.Varint

public object Secp256k1 : KeyGenerator, Signer {
  override val algorithm: Algorithm = JWSAlgorithm.ES256K
  override val keyType: KeyType = KeyType.EC

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L92) */
  public val pubMulticodec: ByteArray = Varint.encode(0xe7)

  /** [reference](https://github.com/multiformats/multicodec/blob/master/table.csv#L169) */
  public val privMultiCodec: ByteArray = Varint.encode(0x1301)

  override fun generatePrivateKey(options: KeyGenOptions?): JWK {
    return ECKeyGenerator(Curve.SECP256K1)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  override fun getPublicKey(privateKey: JWK): JWK {
    require(privateKey is ECKey) { "private key must be an EC Key (kty: EC)" }

    return privateKey.toECKey().toPublicJWK()
  }

  override fun privateKeyToBytes(privateKey: JWK): ByteArray {
    TODO("Not yet implemented")
  }

  override fun publicKeyToBytes(publicKey: JWK): ByteArray {
    TODO("Not yet implemented")
  }

  override fun bytesToPrivateKey(privateKeyBytes: ByteArray): JWK {
    TODO("Not yet implemented")
  }

  override fun bytesToPublicKey(publicKeyBytes: ByteArray): JWK {
    TODO("Not yet implemented")
  }

  override fun sign(privateKey: JWK, payload: Payload, options: SignOptions?): String {
    TODO("Not yet implemented")
  }

  override fun verify(options: VerifyOptions?) {
    TODO("Not yet implemented")
  }
}