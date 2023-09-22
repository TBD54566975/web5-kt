package web5.sdk.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType

// TODO: add hashmap of kid -> JWK that will act as "in-memory keystore"
public class InMemoryKeyManager : KeyManager {
  private val cryptoPrimitives = hashMapOf<Curve, CryptoPrimitive<JWK>>(
    Ed25519.curve to Ed25519,
    Secp256k1.curve to Secp256k1
  )

  // in-memory keystore. flat k/v map where the key is a keyId.
  private val keyStore: MutableMap<String, JWK> = HashMap()
  override fun generatePrivateKey(curve: Curve): String {
    val primitive = cryptoPrimitives[curve] ?: throw Exception("${curve.name} not supported")
    val privateKeyJwk = primitive.generatePrivateKeyJwk()

    keyStore[privateKeyJwk.keyID] = privateKeyJwk

    return privateKeyJwk.keyID
  }

  override fun generatePrivateKey(curve: Curve, options: GenerateOptions): String {
    TODO("not yet implemented")
  }

  // TODO: add optional options. use-case: secp256k1 has uncompressed and compressed public keys
  override fun getPublicKey(alias: String): ByteArray {
    val jwk = keyStore[alias] ?: throw Exception("key with alias $alias not found")
    val primitive = getCryptoPrimitiveForJwk(jwk)

    return primitive.publicKeyJwkToBytes(jwk)
  }

  override fun getPublicKeyJwk(alias: String): JWK {
    val jwk = keyStore[alias] ?: throw Exception("key with alias $alias not found")
    val primitive = getCryptoPrimitiveForJwk(jwk)

    return primitive.getPublicKeyJwk(jwk)
  }

  private fun getCryptoPrimitiveForJwk(jwk: JWK): CryptoPrimitive<JWK> {
    val keyCurve = when (jwk.keyType) {
      KeyType.EC -> jwk.toECKey().curve
      KeyType.OKP -> jwk.toOctetKeyPair().curve
      else -> throw Exception("key type ${jwk.keyType.toJSONString()} not supported")
    }

    return cryptoPrimitives[keyCurve] ?: throw Exception("no crypto primitive for ${keyCurve.name}")
  }
}