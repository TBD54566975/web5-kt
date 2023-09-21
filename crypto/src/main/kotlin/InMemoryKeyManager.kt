package web5.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

// TODO: add hashmap of kid -> JWK that will act as "in-memory keystore"
class InMemoryKeyManager : KeyManager {
  val cryptoPrimitives = hashMapOf<Curve, CryptoPrimitive<JWK>>(
    Ed25519.curve to Ed25519,
    Secp256k1.curve to Secp256k1
  )

  override fun generatePrivateKey(curve: Curve): String {
    val primitive = cryptoPrimitives[curve] ?: throw Exception("${curve.name} not supported")
    val privateKeyJwk = primitive.generatePrivateKeyJwk()

    return privateKeyJwk.keyID
  }

  override fun generatePrivateKey(curve: Curve, options: GenerateOptions): String {
    TODO("not yet implemented")
  }

  // TODO: add optional options. use-case: secp256k1 has uncompressed and compressed public keys
  override fun getPublicKey(alias: String): ByteArray {
    TODO("not yet implemented")
  }

  override fun getPublicKeyJwk(alias: String): JWK {
    TODO("Not yet implemented")
  }
}