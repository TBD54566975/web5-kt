package web5.sdk.crypto

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Payload
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK

public object Crypto {
  private val keyGenerators = mapOf<Algorithm, Map<Curve?, KeyGenerator>>(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519
    ),
    JWSAlgorithm.ES256K to mapOf<Curve?, KeyGenerator>(
      Curve.SECP256K1 to Secp256k1
    )
  )

  private val keyGeneratorsByMultiCodec = mapOf<ByteArray, KeyGenerator>(
    Ed25519.privMultiCodec to Ed25519,
    Ed25519.pubMulticodec to Ed25519,
    Secp256k1.privMultiCodec to Secp256k1,
    Secp256k1.pubMulticodec to Secp256k1
  )

  private val multiCodecsByAlgorithm = mapOf(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519.pubMulticodec
    ),
    JWSAlgorithm.ES256K to mapOf(
      Curve.SECP256K1 to Secp256k1.pubMulticodec
    )
  )

  private val signers = mapOf<Algorithm, Map<Curve?, Signer>>(
    JWSAlgorithm.EdDSA to mapOf(
      Curve.Ed25519 to Ed25519
    ),
    JWSAlgorithm.ES256K to mapOf(
      Curve.SECP256K1 to Secp256k1
    )
  )

  public fun generatePrivateKey(algorithm: Algorithm, curve: Curve? = null, options: KeyGenOptions? = null): JWK {
    val keyGenerator = getKeyGenerator(algorithm, curve)
    return keyGenerator.generatePrivateKey(options)
  }

  public fun sign(privateKey: JWK, payload: Payload, options: SignOptions) {
    val rawCurve = privateKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }


    val signer = getSigner(privateKey.algorithm, curve)

    signer.sign(privateKey, payload, options)
  }

  public fun getPublicKeyBytes(publicKey: JWK): ByteArray {
    val rawCurve = publicKey.toJSONObject()["crv"]
    val curve = rawCurve?.let { Curve.parse(it.toString()) }
    val generator = getKeyGenerator(publicKey.algorithm, curve)

    return generator.publicKeyToBytes(publicKey)
  }

  public fun getKeyGenerator(algorithm: Algorithm, curve: Curve? = null): KeyGenerator {
    val keyGenAlgorithm = keyGenerators.getOrElse(algorithm) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
    }

    val keyGenerator = keyGenAlgorithm.getOrElse(curve) {
      throw IllegalArgumentException("Curve $curve not supported")
    }

    return keyGenerator
  }

  public fun getKeyGenerator(multiCodec: ByteArray): KeyGenerator {
    return keyGeneratorsByMultiCodec.getOrElse(multiCodec) {
      throw IllegalArgumentException("multicodec not supported")
    }
  }

  public fun getSigner(algorithm: Algorithm, curve: Curve? = null): Signer {
    val signerAlgorithm = signers.getOrElse(algorithm) {
      throw IllegalArgumentException("Algorithm $algorithm not supported")
    }

    val signer = signerAlgorithm.getOrElse(curve) {
      throw IllegalArgumentException("Curve $curve not supported")
    }

    return signer
  }
}