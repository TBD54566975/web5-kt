package web5.sdk.dids.methods.dht

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.JWK
import foundation.identity.did.DIDDocument
import foundation.identity.did.Service
import foundation.identity.did.VerificationMethod
import web5.sdk.crypto.Crypto
import web5.sdk.crypto.InMemoryKeyManager
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.PublicKeyPurpose
import java.net.URI
import kotlin.test.Test

class BenchmarkTest {

  @Test
  fun benchmark() {
    val startTime = System.nanoTime()

    repeat(100_000) {
      createDidDhtAndSign()
    }

    val endTime = System.nanoTime()
    val duration = (endTime - startTime) / 1_000_000_000.0  // Convert nanoseconds to seconds

    println("Total time taken: $duration milliseconds")
  }

  private fun createDidDhtAndSign() {
    val options = CreateDidDhtOptions(publish = false)
    val created = otherCreate(options)
    val signed = Crypto.sign(created.second, "Hello World!".toByteArray())
  }

  val keyManager = InMemoryKeyManager()
  val api = DidDhtApi { keyManager }
  fun otherCreate(options: CreateDidDhtOptions?): Pair<DidDht, JWK> {
    val opts = options ?: CreateDidDhtOptions()

    val jwk = Crypto.generatePrivateKey(JWSAlgorithm.EdDSA, Curve.Ed25519)
    val publicKey = jwk.toPublicJWK()
    // build DID Document
    val id = DidDht.getDidIdentifier(publicKey)

    // add identity key to relationships map
    val identityVerificationMethod =
      VerificationMethod.builder()
        .id(URI.create("$id#0"))
        .type("JsonWebKey2020")
        .controller(URI.create(id))
        .publicKeyJwk(publicKey.toJSONObject())
        .build()

    // add all other keys to the verificationMethod and relationships arrays
    val relationshipsMap = mutableMapOf<PublicKeyPurpose, MutableList<VerificationMethod>>().apply {
      val identityVerificationMethodRef = VerificationMethod.builder().id(identityVerificationMethod.id).build()
      listOf(
        PublicKeyPurpose.AUTHENTICATION,
        PublicKeyPurpose.ASSERTION_METHOD,
        PublicKeyPurpose.CAPABILITY_DELEGATION,
        PublicKeyPurpose.CAPABILITY_INVOCATION
      ).forEach { purpose ->
        getOrPut(purpose) { mutableListOf() }.add(identityVerificationMethodRef)
      }
    }

    // map to the DID object model's verification methods
    val verificationMethods = (opts.verificationMethods?.map { (key, purposes) ->
      VerificationMethod.builder()
        .id(URI.create("$id#${key.keyID}"))
        .type("JsonWebKey2020")
        .controller(URI.create(id))
        .publicKeyJwk(key.toPublicJWK().toJSONObject())
        .build().also { verificationMethod ->
          purposes.forEach { relationship ->
            relationshipsMap.getOrPut(relationship) { mutableListOf() }.add(
              VerificationMethod.builder().id(verificationMethod.id).build()
            )
          }
        }
    } ?: emptyList()) + identityVerificationMethod
    opts.services?.forEach { service ->
      requireNotNull(service.id) { "Service id cannot be null" }
      requireNotNull(service.type) { "Service type cannot be null" }
      requireNotNull(service.serviceEndpoint) { "Service serviceEndpoint cannot be null" }
    }
    // map to the DID object model's services
    val services = opts.services?.map { service ->
      Service.builder()
        .id(URI.create("$id#${service.id}"))
        .type(service.type)
        .serviceEndpoint(service.serviceEndpoint)
        .build()
    }

    // build DID Document
    val didDocument =
      DIDDocument.builder()
        .id(URI(id))
        .verificationMethods(verificationMethods)
        .services(services)
        .assertionMethodVerificationMethods(relationshipsMap[PublicKeyPurpose.ASSERTION_METHOD])
        .authenticationVerificationMethods(relationshipsMap[PublicKeyPurpose.AUTHENTICATION])
        .keyAgreementVerificationMethods(relationshipsMap[PublicKeyPurpose.KEY_AGREEMENT])
        .capabilityDelegationVerificationMethods(relationshipsMap[PublicKeyPurpose.CAPABILITY_DELEGATION])
        .capabilityInvocationVerificationMethods(relationshipsMap[PublicKeyPurpose.CAPABILITY_INVOCATION])
        .build()


    return Pair(DidDht(id, keyManager, didDocument, api), jwk)
  }
}