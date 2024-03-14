package web5.sdk.dids.did

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyExporter
import web5.sdk.crypto.KeyImporter
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.VMSelector
import web5.sdk.dids.didcore.VerificationMethod

public typealias DidSigner = (payload: ByteArray) -> ByteArray

public class BearerDid(
  public val did: Did,
  public val keyManager: KeyManager,
  public val document: DidDocument
) {

  public fun getSigner(selector: VMSelector? = null): Pair<DidSigner, VerificationMethod> {
    val verificationMethod = document.selectVerificationMethod(selector)

    val keyAliasResult = runCatching { verificationMethod.publicKeyJwk?.computeThumbprint() }
    val keyAlias = keyAliasResult.getOrNull() ?: throw Exception("Failed to compute key alias")

    val signer: DidSigner = { payload ->
      keyManager.sign(keyAlias.toString(), payload)
    }

    return Pair(signer, verificationMethod)
  }

  public fun export(): PortableDid {

    val keyExporter = keyManager as? KeyExporter
    val privateKeys = mutableListOf<Jwk>()

    document.verificationMethod?.forEach { vm ->
      val keyAliasResult = runCatching { vm.publicKeyJwk?.computeThumbprint() }
      if (keyAliasResult.isSuccess) {
        val keyAlias = keyAliasResult.getOrNull()
        keyExporter?.exportKey(keyAlias!!.toString())?.let { key ->
          privateKeys.add(key)
        }
      }
    }

    return PortableDid(
      uri = this.did.uri,
      document = this.document,
      privateKeys = privateKeys,
      metadata = mapOf()
    )
  }

  public companion object {

    public fun import(
      portableDID: PortableDid,
      keyManager: KeyManager = InMemoryKeyManager()
    ): BearerDid {
      check(portableDID.document.verificationMethod?.size != 0) {
        "PortableDID must contain at least one verification method"
      }

      val allVerificationMethodsHavePublicKey =
        portableDID.document.verificationMethod
          ?.all { vm -> vm.publicKeyJwk != null }
          ?: false

      check(allVerificationMethodsHavePublicKey) {
        "Each VerificationMethod must contain a public key in Jwk format."
      }

      val did = Did.parse(portableDID.uri)

      for (key in portableDID.privateKeys) {
        val keyImporter = keyManager as? KeyImporter
        keyImporter!!.importKey(key)
      }

      return BearerDid(did, keyManager, portableDID.document)
    }
  }

}

