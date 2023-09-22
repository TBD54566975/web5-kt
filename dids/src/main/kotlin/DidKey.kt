package web5.dids

import web5.common.Varint
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import io.ipfs.multibase.Multibase
import web5.crypto.Ed25519
import web5.crypto.InMemoryKeyManager
import web5.crypto.KeyManager
import web5.crypto.Secp256k1
import java.net.URI

val CURVE_CODEC_IDS = mapOf(
  Curve.Ed25519 to Varint.encode(0xed),
  Curve.SECP256K1 to Varint.encode(0xe7)
)

val CODEC_CURVE_IDS = mapOf(
  0xed to Curve.Ed25519,
  0xe7 to Curve.SECP256K1
)

class CreateDidKeyOptions(val curve: Curve = Curve.Ed25519, val keyManager: KeyManager)
class DidState(val did: String, val didDocument: DIDDocument, val keyManager: KeyManager)

object DidKey {
  const val METHOD = "key"

  /**
   * creates a did:key. stores key in an InMemoryKeyManager that's returned from this method
   */
  fun create(): DidState {
    val keyManager = InMemoryKeyManager()
    val defaultOptions = CreateDidKeyOptions(keyManager = keyManager)
    return create(defaultOptions)
  }

  fun create(options: CreateDidKeyOptions): DidState {
    val keyAlias = options.keyManager.generatePrivateKey(options.curve)
    val publicKeyBytes = options.keyManager.getPublicKey(keyAlias)

    val codecId = CURVE_CODEC_IDS.getOrElse(options.curve) {
      throw Exception("${options.curve} curve not supported")
    }

    val idBytes = codecId + publicKeyBytes
    val multibaseEncodedId = Multibase.encode(Multibase.Base.Base58BTC, idBytes)

    val did = "did:key:$multibaseEncodedId"
    val didDocument = resolve(did)

    return DidState(did, didDocument, keyManager = options.keyManager)
  }

  // TODO: return DidResolutionResult instead of DidDocument. hopefully danubetech lib has a type for this
  // TODO: return appropriate DidResolutionResult with error property set instead of throwing exceptions
  // TODO: add support for X25519 derived key
  fun resolve(did: String): DIDDocument {
    val (scheme, method, id) = did.split(':')

    if (scheme != "did") {
      throw IllegalArgumentException("invalid scheme")
    }

    if (method != "key") {
      throw IllegalArgumentException("invalid did method. Method must be 'key'")
    }

    val idBytes = Multibase.decode(id)
    val (codecId, numBytes) = Varint.decode(idBytes)

    val curve = CODEC_CURVE_IDS[codecId]
    val publicKeyBytes = idBytes.drop(numBytes).toByteArray()

    val publicKeyJwk: JWK = when (curve) {
      Curve.Ed25519 -> Ed25519.publicKeyToJwk(publicKeyBytes)
      Curve.SECP256K1 -> Secp256k1.publicKeyToJwk(publicKeyBytes)
      else -> throw IllegalArgumentException("Unsupported curve: $curve")
    }

    val verificationMethodId = URI.create("$did#$id")
    val verificationMethod = VerificationMethod.builder()
      .id(verificationMethodId)
      .publicKeyJwk(publicKeyJwk.toJSONObject())
      .controller(URI(did))
      .type("JsonWebKey2020")
      .build()

    return DIDDocument.builder()
      .id(URI(did))
      .verificationMethod(verificationMethod)
      .build()
  }
}