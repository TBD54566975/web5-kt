package web5.sdk.dids.verificationmethods

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import web5.sdk.crypto.KeyGenOptions
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.PublicKey
import web5.sdk.dids.PublicKeyPurpose
import java.util.UUID

/** Common interface for options available when adding a VerificationMethod. */
public interface VerificationMethodSpec

/** Common interface for classes that can generate a [PublicKey] from a [VerificationMethodSpec]. */
public interface VerificationMethodGenerator {
  /**
   * Generates a [PublicKey] from a [VerificationMethodSpec]. The first element of the pair is an optional id that can
   * be used to identify the private key associated with the generated public key.
   */
  public fun generate(): Pair<String?, PublicKey>
}

/**
 * A [VerificationMethodSpec] where a [KeyManager] will be used to generate the underlying verification method keys.
 * The parameters [algorithm], [curve], and [options] will be forwarded to the keyManager.
 *
 * [relationships] will be used to determine the verification relationships in the DID Document being created.
 * */
public class VerificationMethodCreationParams(
  public val algorithm: Algorithm,
  public val curve: Curve? = null,
  public val options: KeyGenOptions? = null,
  public val relationships: Iterable<PublicKeyPurpose>
) : VerificationMethodSpec {
  internal fun toGenerator(keyManager: KeyManager): VerificationMethodKeyManagerGenerator {
    return VerificationMethodKeyManagerGenerator(keyManager, this)
  }
}

private const val JsonWebKey2020Type = "JsonWebKey2020"

/**
 * A [VerificationMethodSpec] according to https://w3c-ccg.github.io/lds-jws2020/.
 *
 * The [id] property cannot be over 50 chars and must only use characters from the Base64URL character set.
 */
public class JsonWebKey2020VerificationMethod(
  public val id: String,
  public val controller: String? = null,
  public val publicKeyJwk: JWK,
  public val relationships: Iterable<PublicKeyPurpose> = emptySet()
) : VerificationMethodSpec, VerificationMethodGenerator {
  override fun generate(): Pair<String?, PublicKey> {
    return Pair(null, PublicKey(id, JsonWebKey2020Type, controller, publicKeyJwk, relationships))
  }
}

/**
 * A [VerificationMethodSpec] according to https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/.
 *
 * The [id] property cannot be over 50 chars and must only use characters from the Base64URL character set.
 */
public class EcdsaSecp256k1VerificationKey2019VerificationMethod(
  public val id: String,
  public val controller: String? = null,
  public val publicKeyJwk: JWK,
  public val relationships: Iterable<PublicKeyPurpose> = emptySet()
) : VerificationMethodSpec, VerificationMethodGenerator {
  override fun generate(): Pair<String, PublicKey> {
    return Pair(id, PublicKey(id, "EcdsaSecp256k1VerificationKey2019", controller, publicKeyJwk, relationships))
  }
}

internal class VerificationMethodKeyManagerGenerator(
  val keyManager: KeyManager,
  val params: VerificationMethodCreationParams,
) : VerificationMethodGenerator {

  override fun generate(): Pair<String, PublicKey> {
    val alias = keyManager.generatePrivateKey(
      algorithm = params.algorithm,
      curve = params.curve,
      options = params.options
    )
    val publicKeyJwk = keyManager.getPublicKey(alias)
    return Pair(
      alias,
      PublicKey(
        id = UUID.randomUUID().toString(),
        type = JsonWebKey2020Type,
        publicKeyJwk = publicKeyJwk,
        purposes = params.relationships,
      )
    )
  }
}

/**
 * Converts a [VerificationMethodSpec] to a [VerificationMethodGenerator] with the given [keyManager].
 */
public fun VerificationMethodSpec.toGenerator(keyManager: KeyManager): VerificationMethodGenerator {
  return when (this) {
    is VerificationMethodCreationParams -> toGenerator(keyManager)
    is VerificationMethodGenerator -> this
    else -> {
      throw IllegalArgumentException("Unsupported VerificationMethodSpec type: ${this::class.simpleName}")
    }
  }
}

/**
 * Converts a list of [VerificationMethodSpec] to a list of [VerificationMethodGenerator]s with the given [keyManager].
 */
public fun Iterable<VerificationMethodSpec>.toGenerators(keyManager: KeyManager): List<VerificationMethodGenerator> {
  return this.map { it.toGenerator(keyManager) }
}

/**
 * Converts a list of [VerificationMethodSpec] to a list of [PublicKey]s with the given [keyManager].
 */
public fun Iterable<VerificationMethodSpec>.toPublicKeys(keyManager: KeyManager)
  : List<Pair<String?, PublicKey>> = toGenerators(
  keyManager
).map { it.generate() }