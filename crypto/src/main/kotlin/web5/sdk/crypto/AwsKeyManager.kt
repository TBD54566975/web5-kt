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
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.interfaces.ECPublicKey

/**
 * A [KeyManager] that uses AWS KMS for remote storage of keys and signing operations. Caller is expected to provide
 * connection details for [AWSKMS] client as per [Configure the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)
 *
 * Key aliases are generated from the key's JWK thumbprint, and stored in AWS KMS.
 * e.g. alias/6uNnyj7xZUgtKTEOFV2mz0f7Hd3cxIH1o5VXsOo4u1M
 *
 * AWS supports a limited set ECDSA curves for signing:
 * - [JWSAlgorithm.ES256K]
 * - [JWSAlgorithm.ES256]
 * - [JWSAlgorithm.ES384]
 * - [JWSAlgorithm.ES512]
 */
public class AwsKeyManager : KeyManager {

  private val kmsClient: AWSKMS = AWSKMSClientBuilder.standard().build()

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
    val keySpec = getDetails(algorithm).keySpec
    val createKeyRequest = CreateKeyRequest()
      .withKeySpec(keySpec)
      .withKeyUsage(KeyUsageType.SIGN_VERIFY)
    val createKeyResponse = kmsClient.createKey(createKeyRequest)
    val keyId = createKeyResponse.keyMetadata.keyId

    val publicKey = getPublicKey(keyId)
    val alias = getDefaultAlias(publicKey)

    val createAliasRequest = CreateAliasRequest()
      .withAliasName(alias)
      .withTargetKeyId(keyId)
    kmsClient.createAlias(createAliasRequest)
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
   * Signs the provided payload using the private key identified by the provided alias.
   *
   * @param keyAlias The alias referencing the stored private key.
   * @param signingInput The data to be signed.
   * @return The signature in JWS R+S format
   * @throws [AWSKMSException] for any error originating from the [AWSKMS] client
   */
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
   * Return the alias of [publicKey], as was originally returned by [generatePrivateKey]
   *
   * @param publicKey A public key in JWK (JSON Web Key) format
   * @return The alias belonging to [publicKey]
   */
  override fun getDefaultAlias(publicKey: JWK): String {
    val jwkThumbprint = publicKey.computeThumbprint()
    return "alias/$jwkThumbprint"
  }

  /**
   * Parse the ASN.1 DER encoded public key that AWS KMS returns, and convert it to a standard PublicKey
   */
  private fun convertToJavaPublicKey(publicKeyDerBytes: ByteBuffer): PublicKey {
    val publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKeyDerBytes.array())
    return JcaPEMKeyConverter().getPublicKey(publicKeyInfo)
  }

  /**
   * Fetch the [KeySpec] from AWS using a [DescribeKeyRequest]
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

  private fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)
  private fun String.enum(): KeySpec = KeySpec.fromValue(this)

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