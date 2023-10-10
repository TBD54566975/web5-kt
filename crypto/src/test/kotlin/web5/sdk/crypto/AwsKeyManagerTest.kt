package web5.sdk.crypto

import com.amazonaws.AmazonServiceException
import com.amazonaws.auth.AWSStaticCredentialsProvider
import com.amazonaws.auth.BasicAWSCredentials
import com.amazonaws.services.kms.AWSKMSClient
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class AwsKeyManagerTest {

  val signingInput = "The Magic Words are Squeamish Ossifrage".toByteArray()
  val awsKeyManager = AwsKeyManager()

  @Test
  @Disabled
  fun `test key generation`() {
    val alias = awsKeyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val publicKey = awsKeyManager.getPublicKey(alias)

    assertEquals(alias, publicKey.keyID)
    assertEquals(KeyType.EC, publicKey.keyType)
    assertEquals(KeyUse.SIGNATURE, publicKey.keyUse)
    assertEquals(JWSAlgorithm.ES256K, publicKey.algorithm)

  }

  @Test
  @Disabled
  fun `test alias is stable`() {
    val alias = awsKeyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val publicKey = awsKeyManager.getPublicKey(alias)
    val defaultAlias = awsKeyManager.getDefaultAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }

  @Test
  @Disabled
  fun `test signing`() {
    val alias = awsKeyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val signature = awsKeyManager.sign(alias, signingInput)

    //Verify the signature with BouncyCastle via Crypto
    Crypto.verify(
      publicKey = awsKeyManager.getPublicKey(alias),
      signedPayload = signingInput,
      signature = signature
    )
  }

  @Test
  @Disabled
  fun `test a custom KMS client`() {
    val kmsClient = AWSKMSClient.builder()
      .withCredentials(AWSStaticCredentialsProvider(BasicAWSCredentials("foo", "bar")))
      .build()
    val customisedKeyManager = AwsKeyManager(kmsClient = kmsClient)

    assertThrows<AmazonServiceException> {
      customisedKeyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    }
  }
}

