package web5.sdk.crypto

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.kms.AWSKMSClient
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class AwsKeyManagerTest {

  val signingInput = "The Magic Words are Squeamish Ossifrage".toByteArray()

  @Test
  @Disabled("Needs an AWS connection")
  fun `test key generation`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(Algorithm.ES256K)
    val publicKey = awsKeyManager.getPublicKey(alias)

    assertEquals(alias, publicKey.keyID)
    assertEquals(KeyType.EC, publicKey.keyType)
    assertEquals(KeyUse.SIGNATURE, publicKey.keyUse)
    assertEquals(Algorithm.ES256K.name, publicKey.algorithm.name)
  }

  @Test
  @Disabled("Needs an AWS connection")
  fun `test alias is stable`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(Algorithm.ES256K)
    val publicKey = awsKeyManager.getPublicKey(alias)
    val defaultAlias = awsKeyManager.getDeterministicAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }

  @Test
  @Disabled("Needs an AWS connection")
  fun `test signing`() {
    val awsKeyManager = AwsKeyManager()
    val alias = awsKeyManager.generatePrivateKey(Algorithm.ES256K)
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
      customisedKeyManager.generatePrivateKey(Algorithm.ES256K)
    }
  }
}

