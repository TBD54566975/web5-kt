package web5.sdk.crypto

import com.amazonaws.services.kms.AWSKMSClientBuilder
import com.amazonaws.services.kms.model.CreateAliasRequest
import com.amazonaws.services.kms.model.CreateKeyRequest
import com.amazonaws.services.kms.model.DescribeKeyRequest
import com.amazonaws.services.kms.model.GetPublicKeyRequest
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
import com.nimbusds.jose.jwk.KeyUse
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import web5.sdk.common.Base58Btc
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

/**
 * A [KeyManager] that delegates to AWS KMS for storage of keys and signing operations. Key aliases are
 * deterministically generated from base58btc encoding of the public key
 */
public class AwsKeyManager : KeyManager {

  private val kmsClient = AWSKMSClientBuilder.standard().build()

  override fun generatePrivateKey(algorithm: Algorithm, curve: Curve?, options: KeyGenOptions?): String {
    val keySpec = getDetails(algorithm).keySpec
    val createKeyRequest = CreateKeyRequest()
      .withKeySpec(keySpec)
      .withKeyUsage(KeyUsageType.SIGN_VERIFY)
    val createKeyResponse = kmsClient.createKey(createKeyRequest)
    val keyId = createKeyResponse.keyMetadata.keyId

    val getPublicKeyRequest = GetPublicKeyRequest()
      .withKeyId(keyId)
    val publicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest)

    val alias = generateKeyAlias(publicKeyResponse.publicKey)
    val createAliasRequest = CreateAliasRequest()
      .withAliasName(alias)
      .withTargetKeyId(keyId)
    kmsClient.createAlias(createAliasRequest)

    return alias
  }

  override fun getPublicKey(keyAlias: String): JWK {
    val getPublicKeyRequest = GetPublicKeyRequest()
      .withKeyId(keyAlias)
    val publicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest)

    val details = getDetails(publicKeyResponse.keySpec.enum())
    val publicKey = convertToJavaPublicKey(publicKeyResponse.publicKey)

    val jwkBuilder = when (publicKey) {
      is ECPublicKey -> ECKey.Builder(details.curve, publicKey)
      else -> throw IllegalArgumentException("Unknown key type $publicKey")
    }
    return jwkBuilder
      .algorithm(details.algorithm)
      .keyID(keyAlias)
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  /**
   * Parse the ASN.1 DER encoded public key that AWS KMS returns, and convert it to a standard PublicKey
   */
  private fun convertToJavaPublicKey(publicKeyDerBytes: ByteBuffer): PublicKey {
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyDerBytes.array())
    return JcaPEMKeyConverter().getPublicKey(publicKeyInfo)
  }

  override fun sign(keyAlias: String, signingInput: ByteArray): ByteArray {
    val keySpec = fetchKeySpec(keyAlias)
    val details = getDetails(keySpec)
    //Pre-hash the input because AWS limits the message to 4096 bytes
    val hashedMessage = shaDigest(details, signingInput)

    val signRequest = SignRequest()
      .withKeyId(keyAlias)
      .withMessageType(MessageType.DIGEST)
      .withMessage(hashedMessage.asByteBuffer())
      .withSigningAlgorithm(details.signingAlgorithm)
    val signResponse = kmsClient.sign(signRequest)
    val derSignatureBytes = signResponse.signature.array()
    return transcodeDerSignatureToConcat(derSignatureBytes, details.algorithm)
  }

  /**
   * Fetch the [KeySpec] using a [DescribeKeyRequest]
   */
  private fun fetchKeySpec(keyAlias: String): KeySpec {
    val describeKeyRequest = DescribeKeyRequest().withKeyId(keyAlias)
    val describeKeyResponse = kmsClient.describeKey(describeKeyRequest)
    return describeKeyResponse.keyMetadata.keySpec.enum()
  }

  private fun shaDigest(details: Details, signingInput: ByteArray): ByteArray {
    val digest = details.newDigest()
    digest.update(signingInput, 0, signingInput.size)
    val result = ByteArray(digest.digestSize)
    digest.doFinal(result, 0)
    return result
  }

  private data class Details(
    val algorithm: JWSAlgorithm,
    val curve: Curve,
    val keySpec: KeySpec,
    val signingAlgorithm: SigningAlgorithmSpec,
    val newDigest: () -> ExtendedDigest
  )
  private val algorithmDetails = mapOf(
    JWSAlgorithm.ES256K to Details(JWSAlgorithm.ES256K, Curve.SECP256K1, KeySpec.ECC_SECG_P256K1, SigningAlgorithmSpec.ECDSA_SHA_256) { SHA256Digest() },
    JWSAlgorithm.ES256 to Details(JWSAlgorithm.ES256, Curve.P_256, KeySpec.ECC_NIST_P256, SigningAlgorithmSpec.ECDSA_SHA_256) { SHA256Digest() },
    JWSAlgorithm.ES384 to Details(JWSAlgorithm.ES384, Curve.P_384, KeySpec.ECC_NIST_P384, SigningAlgorithmSpec.ECDSA_SHA_384) { SHA384Digest() },
    JWSAlgorithm.ES512 to Details(JWSAlgorithm.ES512, Curve.P_521, KeySpec.ECC_NIST_P521, SigningAlgorithmSpec.ECDSA_SHA_512) { SHA512Digest() }
  )
  private fun getDetails(algorithm: Algorithm): Details {
    return algorithmDetails[algorithm] ?: throw IllegalArgumentException("Algorithm $algorithm is not supported")
  }

  private fun getDetails(keySpec: KeySpec): Details {
    return algorithmDetails.values.firstOrNull { it.keySpec == keySpec }
      ?: throw IllegalArgumentException("KeySpec $keySpec is not supported")
  }

  private fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)
  private fun String.enum(): KeySpec = KeySpec.fromValue(this)

  private fun generateKeyAlias(publicKey: ByteBuffer): String {
    val base58btc = Base58Btc.encode(publicKey.array())
    return "alias/key/$base58btc"
  }

  /**
   * KMS returns the signature encoded as ASN.1 DER. Convert to the "R+S" concatenation format required by JWS
   * https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3.1
   */
  private fun transcodeDerSignatureToConcat(derSignature: ByteArray, algorithm: JWSAlgorithm): ByteArray {
    val signatureLength = ECDSA.getSignatureByteArrayLength(algorithm)
    val jwsSignature = ECDSA.transcodeSignatureToConcat(derSignature, signatureLength)
    ECDSA.ensureLegalSignature(jwsSignature, algorithm) // throws if trash-sig
    return jwsSignature
  }
}