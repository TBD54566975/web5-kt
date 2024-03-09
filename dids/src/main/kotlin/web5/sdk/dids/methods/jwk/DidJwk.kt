package web5.sdk.dids.methods.jwk

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat
import web5.sdk.crypto.AlgorithmId
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.CreateDidOptions
import web5.sdk.dids.DidResolutionMetadata
import web5.sdk.dids.DidResolutionResult
import web5.sdk.dids.ResolutionError
import web5.sdk.dids.ResolveDidOptions
import web5.sdk.dids.did.BearerDID
import web5.sdk.dids.didcore.Did
import web5.sdk.dids.didcore.DIDDocument
import web5.sdk.dids.didcore.Purpose
import web5.sdk.dids.didcore.VerificationMethod
import web5.sdk.dids.exceptions.ParserException
import java.text.ParseException

/**
 * Provides a specific implementation for creating and resolving "did:jwk" method Decentralized Identifiers (DIDs).
 *
 * A "did:jwk" DID is a special type of DID that is formulated directly from a single public key. It's utilized
 * in scenarios where it's beneficial for verifiable credentials, capabilities, or other assertions about a subject
 * to be self-verifiable by third parties. This eradicates the necessity for a separate blockchain or ledger.
 * Further specifics and technical details are outlined in [the DID Jwk Spec](https://example.org/did-method-jwk/).
 *
 * @property uri The URI of the "did:jwk" which conforms to the DID standard.
 * @property keyManager A [keyManager] instance utilized to manage the cryptographic keys associated with the DID.
 *
 * @constructor Initializes a new instance of [DidJwk] with the provided [uri] and [keyManager].
 */
// todo can we make this an object
public class DidJwk {

  public companion object {
    public const val methodName: String = "jwk"

    /**
     * Creates a new "did:jwk" DID, derived from a public key, and stores the associated private key in the
     * provided [keyManager].
     *
     * The method-specific identifier of a "did:jwk" DID is a base64url encoded json web key serialized as a UTF-8
     * string.
     *
     * **Note**: Defaults to ES256K if no options are provided
     *
     * @param keyManager A [keyManager] instance where the new key will be stored.
     * @return A [DidJwk] instance representing the newly created "did:jwk" DID.
     *
     * @throws UnsupportedOperationException if the specified curve is not supported.
     */
    // todo look into whether params can be nullable if providing default values
    public fun create(
      keyManager: KeyManager = InMemoryKeyManager(),
      algorithmId: AlgorithmId = AlgorithmId.Ed25519): BearerDID {

      val keyAlias = keyManager.generatePrivateKey(algorithmId)
      val publicKeyJwk = keyManager.getPublicKey(keyAlias)

      val base64Encoded = Convert(publicKeyJwk.toJSONString()).toBase64Url(padding = false)

      val didUri = "did:jwk:$base64Encoded"

      val did = Did(method = methodName, uri = didUri, url = didUri, id = base64Encoded)

      return BearerDID(did, keyManager, createDocument(did, publicKeyJwk))

    }

    /**
     * Resolves a "did:jwk" DID into a [DidResolutionResult], which contains the DID Document and possible related metadata.
     *
     * This implementation primarily constructs a DID Document with a single verification method derived
     * from the DID's method-specific identifier (the public key).
     *
     * @param did The "did:jwk" DID that needs to be resolved.
     * @return A [DidResolutionResult] instance containing the DID Document and related context.
     *
     * @throws IllegalArgumentException if the provided DID does not conform to the "did:jwk" method.
     */
    public fun resolve(did: String): DidResolutionResult {
      val parsedDid = try {
        Did.parse(did)
      } catch (_: ParserException) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.INVALID_DID.value,
          ),
        )
      }

      if (parsedDid.method != methodName) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.METHOD_NOT_SUPPORTED.value,
          ),
        )
      }

      val id = parsedDid.id
      val decodedKey = Convert(id, EncodingFormat.Base64Url).toStr()
      val publicKeyJwk = try {
        JWK.parse(decodedKey)
      } catch (_: ParseException) {
        return DidResolutionResult(
          context = "https://w3id.org/did-resolution/v1",
          didResolutionMetadata = DidResolutionMetadata(
            error = ResolutionError.INVALID_DID.value
          )
        )
      }

      require(!publicKeyJwk.isPrivate) {
        throw IllegalArgumentException("decoded jwk value cannot be a private key")
      }

      val didDocument = createDocument(parsedDid, publicKeyJwk)

      return DidResolutionResult(didDocument = didDocument, context = "https://w3id.org/did-resolution/v1")
    }

    private fun createDocument(did: Did, publicKeyJwk: JWK): DIDDocument {
      val verificationMethodId = "${did.uri}#0"
      val verificationMethod = VerificationMethod.Builder()
        .id(verificationMethodId)
        .publicKeyJwk(publicKeyJwk)
        .controller(did.url)
        .type("JsonWebKey2020") // todo go impl says JsonWebKey2020 but opting for the new name
        .build()

      val didDocumentBuilder = DIDDocument.Builder()
        .context(listOf("https://www.w3.org/ns/did/v1"))
        .id(did.url)

      // todo noticed that this was already in kotlin impl of building did doc
      // but it's not in go impl?
      // ask frank. encryption not needed for tbdex use, so not considered in go impl
      // keyUse is technically not required (per spec)
      if (publicKeyJwk.keyUse != KeyUse.ENCRYPTION) {
        didDocumentBuilder
          .verificationMethodForPurposes(
            verificationMethod,
            listOf(
              Purpose.AssertionMethod,
              Purpose.Authentication,
              Purpose.CapabilityDelegation,
              Purpose.CapabilityInvocation
            )
          )
      }

      if (publicKeyJwk.keyUse != KeyUse.SIGNATURE) {
        didDocumentBuilder.verificationMethodForPurposes(verificationMethod, listOf(Purpose.KeyAgreement))
      }
      return didDocumentBuilder.build()
    }

    // todo write import() and call bearerdid.import()
  }
}