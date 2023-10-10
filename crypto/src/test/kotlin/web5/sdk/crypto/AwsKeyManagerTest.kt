package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.KeyUse
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertEquals

class AwsKeyManagerTest {

  val signingInput = "The Magic Words are Squeamish Ossifrage".toByteArray()
  val algs = listOf(JWSAlgorithm.ES256K, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
  val awsKeyManager = AwsKeyManager()

  /**
   * Test against actual AWS KMS. Will need to comment before committing
   */
  @Test
//  @Disabled
  fun `test against AWS`() {
    val algs = listOf(JWSAlgorithm.ES256K, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
    algs.forEach { testSigningAlgo(awsKeyManager, it) }
  }

  private fun testSigningAlgo(awsKeyManager: AwsKeyManager, algorithm: JWSAlgorithm) {
    println("Testing $algorithm")
    val alias = awsKeyManager.generatePrivateKey(algorithm)
    println("Alias is $alias")
    val publicKeyJwk = awsKeyManager.getPublicKey(alias)
    println("Public Key JWK: $publicKeyJwk")
    val alias2 = awsKeyManager.getDefaultAlias(publicKeyJwk)
    assertEquals(alias, alias2)

    val signature = awsKeyManager.sign(alias, signingInput)

    if (algorithm == JWSAlgorithm.ES256K)
      Crypto.verify(publicKeyJwk, signingInput, signature)
  }
}

