package web5.sdk.dids

import web5.sdk.crypto.KeyManager

public interface CreateDidOptions

public open class Did(
  public val keyManager: KeyManager,
  public val uri: String
)

public interface DidMethod<T : CreateDidOptions> {
  public val method: String
  public fun create(keyManager: KeyManager, options: T? = null): Did

  public fun resolve(didUrl: String): DidResolutionResult
}