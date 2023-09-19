package web5.dids

import Convert
import Varint
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import java.net.URI
import java.util.UUID

object DidKey {
  // multicodec code for Ed25519 keys
  private val ED25519_CODEC_ID = Varint.encode(0xed)

  fun create(): Pair<String, OctetKeyPair> {
    val jwk = OctetKeyPairGenerator(Curve.Ed25519)
      .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
      .keyID(UUID.randomUUID().toString()) // give the key a unique ID
      .generate()

    val pubJwk = jwk.toPublicJWK()
    val pubKeyBytes = pubJwk.x.decode()

    val idBytes = ED25519_CODEC_ID + pubKeyBytes
    val encodedId = "z${Convert(idBytes).toBase58Btc()}"

    return Pair("did:key:$encodedId", jwk)
  }

  fun resolve(did: String): DIDDocument {
    val (scheme, method, id) = did.split(':')

    if (scheme != "did") {
      throw IllegalArgumentException("invalid scheme")
    }

    if (method != "key") {
      throw IllegalArgumentException("invalid did method. Method must be 'key'")
    }

    val idBytes = Convert(id.substring(1)).toByteArray()
    val publicKeyBytes = idBytes.drop(ED25519_CODEC_ID.size).toByteArray()

    val publicKeyBase64Url = Convert(publicKeyBytes).toStr()

    val jwk = hashMapOf<String, Any>(
      "alg" to "EdDSA",
      "crv" to "Ed25519",
      "kty" to "OKP",
      "use" to "sig",
      "x" to publicKeyBase64Url
    )

    val keyId = URI.create("$did#$id")
    val verificationMethod = VerificationMethod.builder()
      .id(keyId)
      .publicKeyJwk(jwk)
      .controller(URI(did))
      .type("JsonWebKey2020")
      .build()

    return DIDDocument.builder()
      .id(URI(did))
      .verificationMethod(verificationMethod)
      .authenticationVerificationMethod(verificationMethod)
      .assertionMethodVerificationMethod(verificationMethod)
      .capabilityDelegationVerificationMethod(verificationMethod)
      .capabilityInvocationVerificationMethod(verificationMethod)
      .build()
  }
}