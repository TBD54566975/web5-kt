package web5.sdk.dids.did

import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyExporter
import web5.sdk.crypto.KeyImporter
import web5.sdk.crypto.KeyManager
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.didcore.DidDocument
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.Service
import web5.sdk.dids.didcore.VMSelector
import web5.sdk.dids.didcore.VerificationMethod

public typealias DidSigner = (payload: ByteArray) -> ByteArray

/**
 * Represents a Decentralized Identifier (DID) along with its DID document, key manager, metadata,
 * and convenience functions.
 *
 * @param did The Decentralized Identifier (DID) to represent.
 * @param keyManager The KeyManager instance used to manage the cryptographic keys associated with the DID.
 * @param document The DID Document associated with the DID.
 */
public class BearerDid(
  public val uri: String,
  public val did: Did,
  public val keyManager: KeyManager,
  public val document: DidDocument
) {

  /**
   * GetSigner returns a sign method that can be used to sign a payload using a key associated to the DID.
   * This function also returns the verification method needed to verify the signature.
   *
   * Providing the verification method allows the caller to provide the signature's recipient
   * with a reference to the verification method needed to verify the payload. This is often done
   * by including the verification method id either alongside the signature or as part of the header
   * in the case of JSON Web Signatures.
   *
   * The verifier can dereference the verification method id to obtain the public key needed to verify the signature.
   *
   * This function takes a Verification Method selector that can be used to select a specific verification method
   * from the DID Document if desired. If no selector is provided, the payload will be signed with the key associated
   * to the first verification method in the DID Document.
   *
   * The selector can either be a Verification Method ID or a Purpose. If a Purpose is provided, the first verification
   * method in the DID Document that has the provided purpose will be used to sign the payload.
   *
   * The returned signer is a function that takes a byte payload and returns a byte signature.
   */
  @JvmOverloads
  public fun getSigner(selector: VMSelector? = null): Pair<DidSigner, VerificationMethod> {
    val verificationMethod = document.selectVerificationMethod(selector)

    val kid = verificationMethod.publicKeyJwk?.computeThumbprint()
      ?: throw Exception("Failed to compute key alias")

    val signer: DidSigner = { payload ->
      keyManager.sign(kid, payload)
    }

    return Pair(signer, verificationMethod)
  }

  /**
   * Adds a new service to the DID Document and returns a new `BearerDid` instance with the updated document.
   *
   * @param service The service to add to the DID Document.
   * @return A new `BearerDid` instance with the updated DID Document.
   */
  public fun addService(service: Service): BearerDid {
    val updatedServices = document.service?.toMutableList() ?: mutableListOf()
    updatedServices.add(service)
    val updatedDocument = createUpdatedDocument(updatedServices)
    return BearerDid(uri, did, keyManager, updatedDocument)
  }

  /**
   * Deletes a service from the DID Document by its ID and returns a new `BearerDid` instance with the updated document.
   *
   * @param serviceId The ID of the service to delete from the DID Document.
   * @return A new `BearerDid` instance with the updated DID Document.
   */
  public fun deleteService(serviceId: String): BearerDid {
    val updatedServices = document.service?.filter { it.id != serviceId } ?: emptyList()
    val updatedDocument = createUpdatedDocument(updatedServices)
    return BearerDid(uri, did, keyManager, updatedDocument)
  }

  /**
   * Clears all services from the DID Document and returns a new `BearerDid` instance with the updated document.
   *
   * @return A new `BearerDid` instance with the updated DID Document.
   */
  public fun clearServices(): BearerDid {
    val updatedDocument = createUpdatedDocument(emptyList())
    return BearerDid(uri, did, keyManager, updatedDocument)
  }

  /**
   * Creates a new `DidDocument` instance with the updated services.
   *
   * @param updatedServices The updated list of services to include in the DID Document.
   * @return A new `DidDocument` instance with the updated services.
   */
  private fun createUpdatedDocument(updatedServices: List<Service>): DidDocument {
    return DidDocument(
      id = document.id,
      verificationMethod = document.verificationMethod,
      service = updatedServices,
      authentication = document.authentication,
      assertionMethod = document.assertionMethod,
      keyAgreement = document.keyAgreement,
      capabilityInvocation = document.capabilityInvocation,
      capabilityDelegation = document.capabilityDelegation,
      controller = document.controller,
      alsoKnownAs = document.alsoKnownAs
    )
  }

  /**
   * Converts a `BearerDid` object to a portable format containing the URI and verification methods
   * associated with the DID.
   *
   * This method is useful when you need to represent the key material and metadata associated with
   * a DID in format that can be used independently of the specific DID method implementation. It
   * extracts both public and private keys from the DID's key manager and organizes them into a
   * `PortableDid` structure.
   *
   * @returns A `PortableDid` containing the URI, DID document, metadata, and optionally private
   *          keys associated with the `BearerDid`.
   */
  public fun export(): PortableDid {

    check(keyManager is KeyExporter) {
      "KeyManager must implement KeyExporter to export keys"
    }

    val keyExporter = keyManager as KeyExporter
    val privateKeys = mutableListOf<Jwk>()

    document.verificationMethod?.forEach { vm ->
      val keyAliasResult = runCatching { vm.publicKeyJwk?.computeThumbprint() }
      if (keyAliasResult.isSuccess) {
        val keyAlias = keyAliasResult.getOrNull()
        keyExporter.exportKey(keyAlias!!.toString()).let { key ->
          privateKeys.add(key)
        }
      }
    }

    return PortableDid(
      uri = this.uri,
      document = this.document,
      privateKeys = privateKeys,
      metadata = mapOf()
    )
  }

  public companion object {


    /**
     * Instantiates a [BearerDid] object from a given [PortableDid].
     *
     * This method allows for the creation of a `BearerDid` object using a previously created DID's
     * key material, DID document, and metadata.
     *
     * @param portableDid - The PortableDid object to import.
     * @param keyManager - Optionally specify an external Key Management System (KMS) used to
     *                     generate keys and sign data. If not given, a new
     *                     [LocalKeyManager] instance will be created and used.
     * @returns [BearerDid] object representing the DID formed from the
     *          provided PortableDid.
     */
    @JvmOverloads
    public fun import(
      portableDid: PortableDid,
      keyManager: KeyManager = InMemoryKeyManager()
    ): BearerDid {

      check(keyManager is KeyImporter) {
        "KeyManager must implement KeyImporter to import keys"
      }

      check(portableDid.document.verificationMethod?.size != 0) {
        "PortableDID must contain at least one verification method"
      }

      val allVerificationMethodsHavePublicKey =
        portableDid.document.verificationMethod
          ?.all { vm -> vm.publicKeyJwk != null }
          ?: false
      check(allVerificationMethodsHavePublicKey) {
        "Each VerificationMethod must contain a public key in Jwk format."
      }

      val did = Did.parse(portableDid.uri)

      for (key in portableDid.privateKeys) {
        val keyImporter = keyManager as KeyImporter
        keyImporter.importKey(key)
      }

      return BearerDid(portableDid.uri, did, keyManager, portableDid.document)
    }
  }

}

