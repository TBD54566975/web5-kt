package web5.sdk.crypto

import com.nimbusds.jose.JWSAlgorithm
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class InMemoryKeyManagerTest {
  @Test
  fun `test alias is consistent`() {
    val keyManager = InMemoryKeyManager()
    val alias = keyManager.generatePrivateKey(JWSAlgorithm.ES256K)
    val publicKey = keyManager.getPublicKey(alias)
    val defaultAlias = keyManager.getDefaultAlias(publicKey)

    assertEquals(alias, defaultAlias)
  }
}
