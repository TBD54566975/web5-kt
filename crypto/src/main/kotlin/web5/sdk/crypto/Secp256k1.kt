package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator

public class GenerateSecp256k1Options(public val hash: String? = "sha256") : GenerateOptions
public object Secp256k1 : CryptoPrimitive<ECKey> {

  override val algorithm: Algorithm = JWSAlgorithm.ES256K
  override val curve: Curve = Curve.SECP256K1
  override val keyType: KeyType = KeyType.EC
  override val keyUse: KeyUse = KeyUse.SIGNATURE

  override fun generatePrivateKey(): ByteArray {
    return generatePrivateKey(GenerateSecp256k1Options())
  }

  override fun generatePrivateKey(options: GenerateOptions): ByteArray {
    require(options is GenerateSecp256k1Options) { "Invalid Options" }

    return generatePrivateKey(options)
  }

  public fun generatePrivateKey(options: GenerateSecp256k1Options): ByteArray {
    val privateKeyJwk = generatePrivateKeyJwk()
    return privateKeyJwk.d.decode()
  }

  override fun getPublicKey(privateKeyBytes: ByteArray): ByteArray {
    TODO("Not yet implemented")
  }

  override fun generatePrivateKeyJwk(): ECKey {
    return generatePrivateKeyJwk(GenerateSecp256k1Options())
  }

  override fun generatePrivateKeyJwk(options: GenerateOptions): ECKey {
    require(options is GenerateSecp256k1Options) { "Invalid Options" }

    return generatePrivateKeyJwk(options)
  }

  public fun generatePrivateKeyJwk(options: GenerateSecp256k1Options): ECKey {
    return ECKeyGenerator(curve)
      .provider(BouncyCastleProviderSingleton.getInstance())
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  override fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): PublicKeyJwk {
    return privateKeyJwk.toPublicJWK()
  }

  override fun privateKeyToJwk(privateKeyBytes: ByteArray): ECKey {
    TODO("Not yet implemented")
  }

  override fun publicKeyToJwk(publicKeyBytes: ByteArray): JWK {
    TODO("Not yet implemented")
  }

  override fun publicKeyJwkToBytes(jwk: JWK): ByteArray {
    TODO("Not yet implemented")
  }
}