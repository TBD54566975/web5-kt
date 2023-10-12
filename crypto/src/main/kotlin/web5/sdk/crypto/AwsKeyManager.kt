package web5.sdk.crypto

import com.amazonaws.services.kms.AWSKMS
import com.amazonaws.services.kms.AWSKMSClientBuilder
import com.amazonaws.services.kms.model.AWSKMSException
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
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

/**
 * A [KeyManager] that uses AWS KMS for remote storage of keys and signing operations. Caller is expected to provide
 * connection details for [AWSKMS] client as per
 * [Configure the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
 *
 * Key aliases are generated from the key's JWK thumbprint, and stored in AWS KMS.
 * e.g. alias/6uNnyj7xZUgtKTEOFV2mz0f7Hd3cxIH1o5VXsOo4u1M
 *
 * AWSKeyManager supports a limited set ECDSA curves for signing:
 * - [JWSAlgorithm.ES256K]
 */
public class AwsKeyManager @JvmOverloads constructor(
  private val kmsClient: AWSKMS = AWSKMSClientBuilder.standard().build()
) : KeyManager {

  private data class AlgorithmDetails(
    val algorithm: JWSAlgorithm,
    val curve: Curve,
    val keySpec: KeySpec,
    val signingAlgorithm: SigningAlgorithmSpec,
    val newDigest: () -> ExtendedDigest
  )

  private val algorithmDetails = mapOf(
    JWSAlgorithm.ES256K to AlgorithmDetails(
      algorithm = JWSAlgorithm.ES256K,
      curve = Curve.SECP256K1,
      keySpec = KeySpec.ECC_SECG_P256K1,
      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256,
      newDigest = { SHA256Digest() }
    ),
    //Disable some algos that AWS supports, but Crypto doesn't yet
//    JWSAlgorithm.ES256 to AlgorithmDetails(
//      algorithm = JWSAlgorithm.ES256,
//      curve = Curve.P_256,
//      keySpec = KeySpec.ECC_NIST_P256,
//      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_256,
//      newDigest = { SHA256Digest() }
//    ),
//    JWSAlgorithm.ES384 to AlgorithmDetails(
//      algorithm = JWSAlgorithm.ES384,
//      curve = Curve.P_384,
//      keySpec = KeySpec.ECC_NIST_P384,
//      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_384,
//      newDigest = { SHA384Digest() }
//    ),
//    JWSAlgorithm.ES512 to AlgorithmDetails(
//      algorithm = JWSAlgorithm.ES512,
//      curve = Curve.P_521,
//      keySpec = KeySpec.ECC_NIST_P521,
//      signingAlgorithm = SigningAlgorithmSpec.ECDSA_SHA_512,
//      newDigest = { SHA512Digest() }
//    )
  )

  private fun getAlgorithmDetails(algorithm: Algorithm): AlgorithmDetails {
    return algorithmDetails[algorithm] ?: throw IllegalArgumentException("Algorithm $algorithm is not supported")
  }

  private fun getAlgorithmDetails(keySpec: KeySpec): AlgorithmDetails {
    return algorithmDetails.values.firstOrNull { it.keySpec == keySpec }
      ?: throw IllegalArgumentException("KeySpec $keySpec is not supported")
  }

  /**
   * Generates and securely stores a private key based on the provided algorithm and options,
   * returning a unique alias that can be utilized to reference the generated key for future operations.
   *
   * @param algorithm The cryptographic algorithm to use for key generation.
   * @param curve (Optional) The elliptic curve to use (relevant for EC algorithms).
   * @param options (Optional) Additional options to control key generation behavior.
   * @return A unique alias (String) that can be used to reference the stored key.
   * @throws IllegalArgumentException if the [algorithm] is not supported by AWS
   * @throws [AWSKMSException] for any error originating from the [AWSKMS] client
   */
  override fun generatePrivateKey(algorithm: Algorithm, curve: Curve?, options: KeyGenOptions?): String {
    val keySpec = getAlgorithmDetails(algorithm).keySpec
    val createKeyRequest = CreateKeyRequest()
      .withKeySpec(keySpec)
      .withKeyUsage(KeyUsageType.SIGN_VERIFY)
    val createKeyResponse = kmsClient.createKey(createKeyRequest)
    val keyId = createKeyResponse.keyMetadata.keyId

    val publicKey = getPublicKey(keyId)
    val alias = getDeterministicAlias(publicKey)
    setKeyAlias(keyId, alias)
    return alias
  }

  /**
   * Retrieves the public key associated with a previously stored private key, identified by the provided alias.
   *
   * @param keyAlias The alias referencing the stored private key.
   * @return The associated public key in JWK (JSON Web Key) format.
   * @throws [AWSKMSException] for any error originating from the [AWSKMS] client
   */
  override fun getPublicKey(keyAlias: String): JWK {
    val getPublicKeyRequest = GetPublicKeyRequest().withKeyId(keyAlias)
    val publicKeyResponse = kmsClient.getPublicKey(getPublicKeyRequest)
    val publicKey = convertToJavaPublicKey(publicKeyResponse.publicKey)

    val algorithmDetails = getAlgorithmDetails(publicKeyResponse.keySpec.enum())
    val jwkBuilder = when (publicKey) {
      is ECPublicKey -> ECKey.Builder(algorithmDetails.curve, publicKey)
      else -> throw IllegalArgumentException("Unknown key type $publicKey")
    }
    return jwkBuilder
      .algorithm(algorithmDetails.algorithm)
      .keyID(keyAlias)
      .keyUse(KeyUse.SIGNATURE)
      .build()
  }

  /**
   * Signs the provided payload using the private key identified by the provided alias.
   *
   * @param keyAlias The alias referencing the stored private key.
   * @param signingInput The data to be signed.
   * @return The signature in JWS R+S format
   * @throws [AWSKMSException] for any error originating from the [AWSKMS] client
   */
  override fun sign(keyAlias: String, signingInput: ByteArray): ByteArray {
    val keySpec = fetchKeySpec(keyAlias)
    val algorithmDetails = getAlgorithmDetails(keySpec)
    //Pre-hash the input because AWS limits the message to 4096 bytes
    val hashedMessage = shaDigest(algorithmDetails, signingInput)

    val signRequest = SignRequest()
      .withKeyId(keyAlias)
      .withMessageType(MessageType.DIGEST)
      .withMessage(hashedMessage.asByteBuffer())
      .withSigningAlgorithm(algorithmDetails.signingAlgorithm)
    val signResponse = kmsClient.sign(signRequest)
    val derSignatureBytes = signResponse.signature.array()
    return transcodeDerSignatureToConcat(derSignatureBytes, algorithmDetails.algorithm)
  }

  /**
   * Return the alias of [publicKey], as was originally returned by [generatePrivateKey].
   *
   * @param publicKey A public key in JWK (JSON Web Key) format
   * @return The alias belonging to [publicKey]
   */
  override fun getDeterministicAlias(publicKey: JWK): String {
    val jwkThumbprint = publicKey.computeThumbprint()
    return "alias/$jwkThumbprint"
  }

  private fun setKeyAlias(existingAlias: String, newAlias: String) {
    val createAliasRequest = CreateAliasRequest()
      .withAliasName(newAlias)
      .withTargetKeyId(existingAlias)
    kmsClient.createAlias(createAliasRequest)
  }

  /**
   * Parse the ASN.1 DER encoded public key that AWS KMS returns, and convert it to a standard PublicKey.
   */
  private fun convertToJavaPublicKey(publicKeyDerBytes: ByteBuffer): PublicKey {
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyDerBytes.array())
    return JcaPEMKeyConverter().getPublicKey(publicKeyInfo)
  }

  /**
   * Fetch the [KeySpec] from AWS using a [DescribeKeyRequest].
   */
  private fun fetchKeySpec(keyAlias: String): KeySpec {
    val describeKeyRequest = DescribeKeyRequest().withKeyId(keyAlias)
    val describeKeyResponse = kmsClient.describeKey(describeKeyRequest)
    return describeKeyResponse.keyMetadata.keySpec.enum()
  }

  private fun shaDigest(algorithmDetails: AlgorithmDetails, signingInput: ByteArray): ByteArray {
    val digest = algorithmDetails.newDigest()
    digest.update(signingInput, 0, signingInput.size)
    val result = ByteArray(digest.digestSize)
    digest.doFinal(result, 0)
    return result
  }

  private fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)
  private fun String.enum(): KeySpec = KeySpec.fromValue(this)

  /**
   * KMS returns the signature encoded as ASN.1 DER. Convert to the "R+S" concatenation format required by JWS.
   * https://www.rfc-editor.org/rfc/rfc7515#appendix-A.3.1
   */
  private fun transcodeDerSignatureToConcat(derSignature: ByteArray, algorithm: JWSAlgorithm): ByteArray {
    val signatureLength = ECDSA.getSignatureByteArrayLength(algorithm)
    val jwsSignature = ECDSA.transcodeSignatureToConcat(derSignature, signatureLength)
    ECDSA.ensureLegalSignature(jwsSignature, algorithm) // throws if trash-sig
    return jwsSignature
  }
}