package web5.sdk.crypto

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.kms.AWSKMSClient
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AwsKeyManagerTest {

  val signingInput = "The Magic Words are Squeamish Ossifrage".toByteArray()

  @Test
  @Disabled("Needs an AWS connection")
  fun `test key generation`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val publicKey = awsKeyManager.getPublicKey(alias)

    assertEquals(alias, publicKey.keyID)
    assertTrue(publicKey is ECKey)
    assertEquals(KeyUse.SIGNATURE, publicKey.keyUse)
    assertEquals(JWSAlgorithm.ES256K, publicKey.algorithm)
  }

  @Test
  @Disabled("Needs an AWS connection")
  fun `test alias is stable`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val publicKey = awsKeyManager.getPublicKey(alias)
    val defaultAlias = awsKeyManager.getDeterministicAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }

  @Test
  @Disabled("Needs an AWS connection")
  fun `test signing`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(AlgorithmId.secp256k1)
    val signature = awsKeyManager.sign(alias, signingInput)

    //Verify the signature with BouncyCastle via Crypto
    Crypto.verify(
      publicKey = awsKeyManager.getPublicKey(alias),
      signedPayload = signingInput,
      signature = signature
    )
  }

  @Test
  @Disabled("Needs an AWS connection")
  fun `test a custom KMS client`() {
    val kmsClient = AWSKMSClient.builder()
      .withCredentials(AWSStaticCredentialsProvider(BasicAWSCredentials("foo", "bar")))
      .build()
    val customisedKeyManager = AwsKeyManager(kmsClient = kmsClient)

    assertThrows<AmazonServiceException> {
      customisedKeyManager.generatePrivateKey(AlgorithmId.secp256k1)
    }
  }
}

