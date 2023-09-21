package web5.dids

import com.identityfoundry.ddi.protocol.multicodec.Multicodec
import com.identityfoundry.ddi.protocol.multicodec.MulticodecEncoder
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.util.Base64URL
import foundation.identity.did.DID
import foundation.identity.did.DIDDocument
import foundation.identity.did.VerificationMethod
import io.ipfs.multibase.Multibase
import java.net.URI

private val JWK.decodedX: ByteArray?
  get() {
    return when (this.keyType) {
      KeyType.OKP -> this.toOctetKeyPair().decodedX
      KeyType.EC -> this.toECKey().x.decode()
      else -> null
    }
  }
private val JWK.multicodec: Multicodec?
  get() {
    return when (this.keyType) {
      KeyType.OKP -> this.toOctetKeyPair().toMulticodec()
      KeyType.EC -> this.toECKey().toMulticodec()
      else -> null
    }
  }

private fun ECKey.toMulticodec(): Multicodec? {
  return when (this.curve) {
    Curve.P_256 -> {
      require(!this.isPrivate)
      Multicodec.P256_PUB
    }

    else -> null
  }
}

private fun OctetKeyPair.toMulticodec(): Multicodec? {
  return when (this.curve) {
    Curve.Ed25519 -> {
      if (this.isPrivate) {
        Multicodec.ED25519_PRIV
      } else {
        Multicodec.ED25519_PUB
      }
    }

    else -> null
  }
}

public object DIDKeyMethod : DIDMethod {
  override fun authorize(operation: DIDMethodOperation, authorization: AuthorizationInfo?): Boolean {
    when (operation) {
      is DIDCreator -> {
        return true
      }
    }
    return false
  }

  override fun creator(opts: CreateDIDOptions): DIDCreator {
    require(opts is CreateDIDKeyOptions)
    require(!opts.publicJwk.isPrivate)
    return DIDKeyCreator(opts.publicJwk)
  }
}

public class DIDKeyCreationMetadata(public val jwk: JWK) : DIDCreationMetadata
private class DIDKeyCreator(
  private val jwk: JWK,
) : DIDCreator {
  override fun create(): DIDCreationResult {
    val methodSpecId: String = Multibase.encode(
      Multibase.Base.Base58BTC,
      MulticodecEncoder.encode(jwk.multicodec, jwk.toPublicJWK().decodedX)
    )

    val identifier = "did:key:$methodSpecId"
    val didDocument = createDocument(identifier)

    return DIDCreationResult(
      DID.fromString(identifier),
      didDocument,
    )
  }

  private fun createSignatureMethod(did: DID): VerificationMethod {
    val multibaseValue = did.methodSpecificId
    val decodedMultibase = Multibase.decode(multibaseValue)

    // TODO: The decode function is not unambiguous. See https://github.com/richardbergquist/java-multicodec#current-workarounds
    val decodedData = MulticodecEncoder.decode(decodedMultibase)
    val multicodecValue = decodedData.codec
    val rawPublicKeyBytes = decodedData.dataAsBytes

    require(rawPublicKeyBytes.size == expectedPublicKeySize(multicodecValue))

    return VerificationMethod.builder()
      .id(URI.create(did.toUri().toString() + "#$multibaseValue"))
      .type("JsonWebKey2020")
      .controller(did.toUri())
      .publicKeyJwk(encodeJWK(multicodecValue, rawPublicKeyBytes)!!.toJSONObject())
      .build()
  }

  private fun expectedPublicKeySize(multicodecValue: Multicodec): Int {
    // from https://w3c-ccg.github.io/did-method-key/#signature-method-creation-algorithm
    //    0xe7	33 bytes	secp256k1-pub - Secp256k1 public key (compressed)
    //    0xec	32 bytes	x25519-pub - Curve25519 public key
    //    0xed	32 bytes	ed25519-pub - Ed25519 public key
    //    0x1200	33 bytes	p256-pub - P-256 public key (compressed)
    //    0x1201	49 bytes	p384-pub - P-384 public key (compressed)
    return when (multicodecValue) {
      Multicodec.SECP256K1_PUB -> 33
      Multicodec.X25519_PUB -> 32
      Multicodec.ED25519_PUB -> 32
      Multicodec.P256_PUB -> 33
      Multicodec.P384_PUB -> 49
      else -> -1
    }
  }

  private fun encodeJWK(multicodecValue: Multicodec, rawPublicKeyBytes: ByteArray): OctetKeyPair? {
    val curve = multicodecValue.toCurve()
    require(curve != null)
    return OctetKeyPair.Builder(curve, Base64URL.encode(rawPublicKeyBytes)).build()
  }

  private fun createDocument(identifier: String): DIDDocument {
    val did = DID.fromString(identifier)
    require(did.methodName == "key")
    require(did.methodSpecificId.startsWith('z'))
    val signatureVerificationMethod: VerificationMethod = createSignatureMethod(did)
    val idOnly = VerificationMethod.builder().id(signatureVerificationMethod.id).build()
    return DIDDocument.builder().id(URI.create(identifier))
      .verificationMethod(signatureVerificationMethod)
      .authenticationVerificationMethod(idOnly)
      .assertionMethodVerificationMethod(idOnly)
      .capabilityInvocationVerificationMethod(idOnly)
      .capabilityDelegationVerificationMethod(idOnly)
      .build()
  }
}

public class CreateDIDKeyOptions(
  public val publicJwk: JWK
) : CreateDIDOptions

private fun Multicodec.toCurve(): Curve? {
  return when (this) {
    Multicodec.SECP256K1_PUB -> Curve.SECP256K1
    Multicodec.X25519_PUB -> Curve.X25519
    Multicodec.ED25519_PUB -> Curve.Ed25519
    Multicodec.P256_PUB -> Curve.P_256
    Multicodec.P384_PUB -> Curve.P_384
    else -> null
  }
}