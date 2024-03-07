package web5.sdk.dids.did

import com.nimbusds.jose.jwk.JWK
import web5.sdk.crypto.KeyExporter
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.VMSelector
import web5.sdk.dids.didcore.VerificationMethod

public typealias DIDSigner = (payload: ByteArray) -> ByteArray

public class BearerDID(
  public val did: Did,
  public val keyManager: KeyManager,
  public val document: DIDDocument
) {

  public fun getSigner(selector: VMSelector): Pair<DIDSigner?, VerificationMethod?> {
    val verificationMethod = document.selectVerificationMethod(selector)

    val keyAliasResult = runCatching { verificationMethod.publicKeyJwk?.computeThumbprint() }
    val keyAlias = keyAliasResult.getOrNull() ?: throw Exception("Failed to compute key alias")

    val signer: DIDSigner = { payload ->
      keyManager.sign(keyAlias.toString(), payload)
    }

    return Pair(signer, verificationMethod)
  }

  public fun export() : PortableDID {

    val keyExporter = keyManager as? KeyExporter
    val privateKeys = mutableListOf<JWK>()

    document.verificationMethod?.forEach { vm ->
      val keyAliasResult = runCatching { vm.publicKeyJwk?.computeThumbprint() }
      if (keyAliasResult.isSuccess) {
        val keyAlias = keyAliasResult.getOrNull()
        keyExporter?.exportKey(keyAlias!!.toString())?.let { key ->
          privateKeys.add(key)
        }
      }
    }

    return PortableDID(
      uri = this.did.uri,
      document = this.document,
      privateKeys = privateKeys,
      metadata = mapOf()
    )
  }

  // todo swift doesn't have import() but go and js does. do i write that or nah
}