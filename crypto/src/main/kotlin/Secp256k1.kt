package web5.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator

object Secp256k1 {
  fun algorithm(): Algorithm {
    return JWSAlgorithm.ES256K
  }

  fun curve(): Curve {
    return Curve.SECP256K1
  }

  fun keyType(): KeyType {
    return KeyType.EC
  }

  fun generatePrivateKey(): ByteArray {
    val privateKeyJwk = Secp256k1.generatePrivateKeyJwk()
    return privateKeyJwk.decodedD
  }

  fun generatePrivateKeyJwk(): PrivateKeyJwk {
    return OctetKeyPairGenerator(curve())
      .provider(BouncyCastleProviderSingleton.getInstance())
      .keyIDFromThumbprint(true)
      .keyUse(KeyUse.SIGNATURE)
      .generate()
  }

  fun getPublicKeyJwk(privateKeyJwk: PrivateKeyJwk): PublicKeyJwk {
    return privateKeyJwk.toPublicJWK()
  }
}