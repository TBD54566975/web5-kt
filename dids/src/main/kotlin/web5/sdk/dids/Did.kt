package web5.sdk.dids

import web5.sdk.crypto.KeyManager

public open class Did(
  public val keyManager: KeyManager,
  public val uri: String
)