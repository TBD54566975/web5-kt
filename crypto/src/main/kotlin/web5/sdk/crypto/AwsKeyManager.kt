package web5.sdk.crypto

import com.amazonaws.services.kms.AWSKMSClientBuilder
import com.amazonaws.services.kms.model.CreateAliasRequest
import com.amazonaws.services.kms.model.CreateKeyRequest
import com.amazonaws.services.kms.model.DescribeKeyRequest
import com.amazonaws.services.kms.model.GetPublicKeyRequest
import com.amazonaws.services.kms.model.GetPublicKeyResult
import com.amazonaws.services.kms.model.KeySpec
import com.amazonaws.services.kms.model.KeyUsageType
import com.amazonaws.services.kms.model.MessageType
import com.amazonaws.services.kms.model.SignRequest
import com.amazonaws.services.kms.model.SigningAlgorithmSpec
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import web5.sdk.common.Convert
import java.nio.ByteBuffer
import java.security.interfaces.ECPublicKey

public fun main() {
  val keyManager = AWSKeyManager()
//  val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K, Curve.SECP256K1, null)
  val publicKey = keyManager.getPublicKey("alias/did_key_1234")
  println(publicKey.toJSONString())

  val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
    .keyID("theKey")
    .build()

  val payload = Payload(mapOf())
  val jwsObject = JWSObject(header, payload)
  val signature = keyManager.sign(
    "alias/did_key_1234",
//    Payload("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ")
    ByteArray(50) { i -> i.toByte() }
  )
  println(signature)
}

public class AWSKeyManager
  : KeyManager {

  private val kmsClient = AWSKMSClientBuilder.standard().build()

  override fun generatePrivateKey(algorithm: Algorithm, curve: Curve?, options: KeyGenOptions?): String {
    val keySpec = getKeySpec(algorithm)
    val createKeyRequest = CreateKeyRequest()
      .withKeySpec(keySpec)
      .withKeyUsage(KeyUsageType.SIGN_VERIFY)
    //TODO handle sad day
    val createKeyResponse = kmsClient.createKey(createKeyRequest)
    val keyId = createKeyResponse.keyMetadata.keyId

    val getPublicKeyRequest = GetPublicKeyRequest()
      .withKeyId(keyId)
    //TODO handle sad day
    val publicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest)

    //TODO implement base58 stuff properly
    val didKey = toEncodedId(publicKeyResponse)
    val alias = toAlias(didKey)

    val createAliasRequest = CreateAliasRequest()
      .withAliasName(alias)
      .withTargetKeyId(keyId)
    //TODO handle sad day
    val createAliasResponse = kmsClient.createAlias(createAliasRequest)

    return alias
  }

  override fun getPublicKey(keyAlias: String): JWK {
    val getPublicKeyRequest = GetPublicKeyRequest()
      .withKeyId(keyAlias)
    //TODO handle sad day
    val publicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest)

    return convertDERPublicKeyToJWK(publicKeyResponse)
  }

  private fun convertDERPublicKeyToJWK(publicKeyResponse: GetPublicKeyResult): JWK {
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyResponse.publicKey.array())
    val publicKey = JcaPEMKeyConverter().getPublicKey(publicKeyInfo)
    val curveOID = publicKeyInfo.algorithm.parameters.toString()
    val curve = Curve.forOID(curveOID)
    return when (publicKey) {
      is ECPublicKey -> ECKey.Builder(curve, publicKey).build()
      else -> throw IllegalArgumentException("Unknown key type $publicKey")
    }
  }

  override fun sign(keyAlias: String, signingInput: ByteArray): ByteArray {
    val keySpec = getKeySpec(keyAlias)

    val hashedMessage = getDigestForKeySpec(keySpec).doDigest(signingInput)

    val signRequest = SignRequest()
      .withKeyId(keyAlias)
      .withMessageType(MessageType.DIGEST)
      .withMessage(hashedMessage.asByteBuffer())
      .withSigningAlgorithm(getSigningAlgorithm(keySpec))
    val signResponse = kmsClient.sign(signRequest)
    val derSignatureBytes = signResponse.signature.array()
    return transcodeDerToConcat(derSignatureBytes, getAlgorithm(keySpec))
  }

  private fun getKeySpec(keyAlias: String): KeySpec {
    val describeKeyRequest = DescribeKeyRequest().withKeyId(keyAlias)
    val describeKeyResponse = kmsClient.describeKey(describeKeyRequest)
    val keySpec = describeKeyResponse.keyMetadata.keySpec
    return KeySpec.fromValue(keySpec)
  }

  private fun getDigestForKeySpec(keySpec: KeySpec): ExtendedDigest = when (keySpec) {
    KeySpec.ECC_SECG_P256K1 -> SHA256Digest()
    KeySpec.ECC_NIST_P256 -> SHA256Digest()
    KeySpec.ECC_NIST_P384 -> SHA384Digest()
    KeySpec.ECC_NIST_P521 -> SHA512Digest()
    else -> throw IllegalArgumentException("Unknown KeySpec $keySpec")
  }

  private fun getSigningAlgorithm(keySpec: KeySpec) = when (keySpec) {
    KeySpec.ECC_SECG_P256K1 -> SigningAlgorithmSpec.ECDSA_SHA_256
    KeySpec.ECC_NIST_P256 -> SigningAlgorithmSpec.ECDSA_SHA_256
    KeySpec.ECC_NIST_P384 -> SigningAlgorithmSpec.ECDSA_SHA_384
    KeySpec.ECC_NIST_P521 -> SigningAlgorithmSpec.ECDSA_SHA_512
    else -> throw IllegalArgumentException("Unknown KeySpec $keySpec")
  }

  private val algorithms = mapOf<JWSAlgorithm, KeySpec>(
    JWSAlgorithm.ES256K to KeySpec.ECC_SECG_P256K1,
    JWSAlgorithm.ES256 to KeySpec.ECC_NIST_P256,
    JWSAlgorithm.ES384 to KeySpec.ECC_NIST_P384,
    JWSAlgorithm.ES512 to KeySpec.ECC_NIST_P521
  )
  private fun getKeySpec(algorithm: Algorithm): KeySpec {
    return algorithms[algorithm]
      ?: throw IllegalArgumentException("Algorithm $algorithm is not supported")
  }

  private fun getAlgorithm(keySpec: KeySpec): JWSAlgorithm {
    return algorithms.entries.firstOrNull { it.value == keySpec }?.key
      ?: throw IllegalArgumentException("KeySpec $keySpec is not supported")
  }

  private fun ExtendedDigest.doDigest(input: ByteArray): ByteArray {
    this.update(input, 0, input.size)
    val result = ByteArray(this.digestSize)
    this.doFinal(result, 0)
    return result
  }

  private fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)

  private fun toAlias(didKey: String): String {
    val mungedDID = didKey.replace(":", "_")
    return "alias/$mungedDID"
  }

  private fun toEncodedId(publicKeyResponse: GetPublicKeyResult): String {
    publicKeyResponse.publicKey

//    val publicKeyBytes = Crypto.getPublicKeyBytes(publicKey)
//
//    val codecId = CURVE_CODEC_IDS.getOrElse(opts.curve) {
//      throw UnsupportedOperationException("${opts.curve} curve not supported")
//    }
//
//    val idBytes = codecId + publicKeyBytes
//    val multibaseEncodedId = Multibase.encode(Multibase.Base.Base58BTC, idBytes)

    return "did:key:1234"
  }

  /**
   * KMS returns the signature encoded as ASN.1 DER. Convert to the "R+S" concatenation format required by JWS
   * https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3.1
   */
  private fun transcodeDerToConcat(derSignatureBytes: ByteArray, algorithm: JWSAlgorithm): ByteArray {
    val signatureLength = ECDSA.getSignatureByteArrayLength(algorithm)
    val jwsSignatureBytes = ECDSA.transcodeSignatureToConcat(derSignatureBytes, signatureLength)
    ECDSA.ensureLegalSignature(jwsSignatureBytes, algorithm) // throws if trash-sig
    return jwsSignatureBytes
  }
}