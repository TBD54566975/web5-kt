package sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import org.junit.jupiter.api.Test
import web5.sdk.crypto.AwsKeyManager
import web5.sdk.crypto.Crypto

class AwsKeyManagerTest {

  val signingInput = "The Magic Words are Squeamish Ossifrage".toByteArray()

  @Test
  fun `test against AWS`() {
    val awsKeyManager = AwsKeyManager()

    val algs = listOf(JWSAlgorithm.ES256K, JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
    algs.forEach { testSigningAlgo(awsKeyManager, it) }
  }

  private fun testSigningAlgo(awsKeyManager: AwsKeyManager, algorithm: JWSAlgorithm) {
    println("Testing $algorithm")
    val alias = awsKeyManager.generatePrivateKey(algorithm)
    println("Alias is $alias")
    val publicKeyJwk = awsKeyManager.getPublicKey(alias)
    println("Public Key JWK: $publicKeyJwk")
    val signature = awsKeyManager.sign(alias, signingInput)

    if (algorithm == JWSAlgorithm.ES256K)
      Crypto.verify(publicKeyJwk, signingInput, signature)
  }
}

