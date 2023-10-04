package web5.sdk.dids

import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import io.ipfs.multibase.Multibase
import web5.sdk.common.Varint
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.KeyManager
import java.net.URI

private val CURVE_CODEC_IDS = mapOf(
  Curve.Ed25519 to Varint.encode(0xed),
  Curve.SECP256K1 to Varint.encode(0xe7)
)

public class CreateDidKeyOptions(
  public val algorithm: Algorithm = JWSAlgorithm.EdDSA,
  public val curve: Curve = Curve.Ed25519,
) : CreateDidOptions


public typealias DidKey = Did

public object DidKeyMethod : DidMethod<CreateDidKeyOptions> {
  override val method: String = "key"

  /**
   * creates a did:key. stores key in a keymanager that's returned from this method
   */
  override fun create(keyManager: KeyManager, options: CreateDidKeyOptions?): DidKey {
    val opts = options ?: CreateDidKeyOptions()

    val keyAlias = keyManager.generatePrivateKey(opts.algorithm, opts.curve)
    val publicKey = keyManager.getPublicKey(keyAlias)
    val publicKeyBytes = Crypto.getPublicKeyBytes(publicKey)

    val codecId = CURVE_CODEC_IDS.getOrElse(opts.curve) {
      throw UnsupportedOperationException("${opts.curve} curve not supported")
    }

    val idBytes = codecId + publicKeyBytes
    val multibaseEncodedId = Multibase.encode(Multibase.Base.Base58BTC, idBytes)

    val did = "did:key:$multibaseEncodedId"

    return DidKey(keyManager, did)
  }


  // TODO: return appropriate DidResolutionResult with error property set instead of throwing exceptions
  // TODO: add support for X25519 derived key
  override fun resolve(did: String): DidResolutionResult {
    val parsedDid = DID.fromString(did)

    require(parsedDid.methodName == method) { throw IllegalArgumentException("expected did:key") }

    val id = parsedDid.methodSpecificId
    val idBytes = Multibase.decode(id)
    val (codecId, numBytes) = Varint.decode(idBytes)

    val publicKeyBytes = idBytes.drop(numBytes).toByteArray()

    val keyGenerator = Crypto.getKeyGenerator(Varint.encode(codecId))
    val publicKeyJwk = keyGenerator.bytesToPublicKey(publicKeyBytes)

    val verificationMethodId = URI.create("$did#$id")
    val verificationMethod = VerificationMethod.builder()
      .id(verificationMethodId)
      .publicKeyJwk(publicKeyJwk.toJSONObject())
      .controller(URI(did))
      .type("JsonWebKey2020")
      .build()

    val didDocument = DIDDocument.builder()
      .id(URI(did))
      .verificationMethod(verificationMethod)
      .build()

    return DidResolutionResult(didDocument = didDocument, context = "https://w3id.org/did-resolution/v1")
  }
}