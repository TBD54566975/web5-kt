package web5.credentials

import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import foundation.identity.did.DIDDocument
import foundation.identity.jsonld.JsonLDObject
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.assertThrows
import uniresolver.result.ResolveDataModelResult
import uniresolver.result.ResolveRepresentationResult
import uniresolver.w3c.DIDResolver
import web5.credentials.model.ConstraintsV2
import web5.credentials.model.CredentialStatus
import web5.credentials.model.CredentialSubject
import web5.credentials.model.FieldV2
import web5.credentials.model.InputDescriptorV2
import web5.credentials.model.PresentationDefinitionV2
import web5.credentials.model.VerifiableCredentialType
import java.net.URI
import java.util.Date
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SSITest {
  lateinit var signOptions: SignOptions
  lateinit var didKey: Triple<JWK, String, DIDDocument>
  lateinit var did: String
  lateinit var didDocument: DIDDocument

  @BeforeEach
  fun setup() {
    didKey = DIDKey.generateEd25519()
    did = didKey.second
    didDocument = didKey.third

    signOptions = SignOptions(
      kid = "#" + did.split(":")[2],
      issuerDid = did,
      subjectDid = did,
      signerPrivateKey = didKey.first
    )
  }

  @Test
  fun `generate did key returns valid key`() {
    assertContains(DIDKey.generateEd25519().second, "did:key:z6Mk")
  }

  @Test
  fun `creates vc with createVCOptions returns valid vc jwt`() {
    val claims: MutableMap<String, Any> = LinkedHashMap()
    val degree: MutableMap<String, Any> = LinkedHashMap()
    degree["name"] = "Bachelor of Science and Arts"
    degree["type"] = "BachelorDegree"
    claims["college"] = "Test University"
    claims["degree"] = degree

    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(didKey.second))
      .claims(claims)
      .build()

    val vcCreateOptions = CreateVcOptions(
      credentialSubject = credentialSubject,
      issuer = did,
      expirationDate = null,
      credentialStatus = null
    )

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, vcCreateOptions, null)

    val signedJWT = SignedJWT.parse(vcJwt)
    val payload = signedJWT.payload.toJSONObject()

    assertEquals("EdDSA", signedJWT.header.algorithm.name)
    assertEquals("JWT", signedJWT.header.type.toString())
    assertTrue { payload.containsKey("iss") }
    assertTrue { payload.containsKey("sub") }

    assertTrue {
      VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument))
    }
  }

  @Test
  fun `creates vc with valid vc builder returns vc jwt`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)
    assertTrue(VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `creates credential status vc with valid vc builder returns vc jwt`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["firstName"] = "Bobby" })
      .build()

    val properties = mapOf(
      "statusPurpose" to "revocation",
      "statusListIndex" to "94567",
      "statusListCredential" to "https://example.com/credentials/status/3"
    )

    val credentialStatus: CredentialStatus = CredentialStatus.builder()
      .base(
        JsonLDObject.builder()
          .id(URI.create("https://example.com/credentials/status/3#94567"))
          .type("StatusList2021Entry")
          .properties(properties)
          .build()
      )
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .credentialStatus(credentialStatus)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)
    assertTrue(VerifiableCredential.verify(vcJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `fulfills presentation definition with valid vcjwt`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["btcAddress"] = "btcAddress123" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)

    val btcAddressPd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(fields = listOf(buildField(paths = arrayOf("$.credentialSubject.btcAddress"))))
      )
    )

    val createVpOptions =
      CreateVpOptions(btcAddressPd, arrayListOf(vcJwt), did)
    val vpJwt: VpJwt = VerifiablePresentation.create(signOptions, createVpOptions)

    val signedJWT = SignedJWT.parse(vpJwt)
    val payload = signedJWT.payload.toJSONObject()

    assertEquals("EdDSA", signedJWT.header.algorithm.name)
    assertEquals("JWT", signedJWT.header.type.toString())
    assertTrue(payload.containsKey("iss"))
    assertTrue(payload.containsKey("sub"))
    assertTrue(payload.containsKey("vp"))
  }

  @Test
  fun `presentation definition is not fulfilled`() {
    val credentialSubject = CredentialSubject.builder()
      .id(URI.create(did))
      .claims(mutableMapOf<String, Any>().apply { this["something"] = "notgood" })
      .build()

    val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
      .id(URI.create(UUID.randomUUID().toString()))
      .credentialSubject(credentialSubject)
      .issuer(URI.create(did))
      .issuanceDate(Date())
      .build()

    val vcJwt: VcJwt = VerifiableCredential.create(signOptions, null, vc)

    val btcAddressPd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(fields = listOf(buildField(paths = arrayOf("$.credentialSubject.btcAddress"))))
      )
    )

    val createVpOptions =
      CreateVpOptions(btcAddressPd, arrayListOf(vcJwt), did)

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception
        .message!!.contains("is not satisfied in InputDescriptor")
    )
  }

  @Test
  fun `should throw exception when only btcAddress VcJwt is passed`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val btcAddressVcJwt = buildVcJwt(did = did, signOptions, mapOf("btcAddress" to "btcAddress123"))

    val createVpOptions =
      CreateVpOptions(
        btcAddressFirstNamePd,
        arrayListOf(btcAddressVcJwt),
        did
      )

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception.message!!.contains("Required field firstNameId is not satisfied in InputDescriptor")
    )
  }

  @Test
  fun `should throw exception when two identical btcAddress VcJwts are passed`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val btcAddressVcJwt = buildVcJwt(did = did, signOptions, mapOf("btcAddress" to "btcAddress123"))

    val createVpOptions = CreateVpOptions(
      btcAddressFirstNamePd,
      arrayListOf(btcAddressVcJwt, btcAddressVcJwt),
      did
    )

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception.message!!.contains("Required field firstNameId is not satisfied in InputDescriptor")
    )
  }

  @Test
  fun `should verify successfully when both required VcJwts are passed`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val btcAddressVcJwt = buildVcJwt(did = did, signOptions, mapOf("btcAddress" to "btcAddress123"))
    val firstNameVcJwt = buildVcJwt(did = did, signOptions, mapOf("firstName" to "bob"))


    val createVpOptions = CreateVpOptions(
      btcAddressFirstNamePd,
      arrayListOf(btcAddressVcJwt, firstNameVcJwt),
      did
    )

    val vpJwt: VpJwt = VerifiablePresentation.create(signOptions, createVpOptions)

    assertTrue(VerifiablePresentation.verify(vpJwt, SimpleResolver(didDocument)))
  }

  @Test
  fun `should throw exception when VCJwts is an empty list`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val createVpOptions = CreateVpOptions(btcAddressFirstNamePd, arrayListOf(), did)

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception.message!!.contains("Required field btcAddressId is not satisfied in InputDescriptor")
    )
  }

  @Test
  fun `should throw exception when VCJwts is invalid`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val createVpOptions =
      CreateVpOptions(btcAddressFirstNamePd, arrayListOf("invalidjwt"), did)

    val exception = assertThrows<Exception> {
      VerifiablePresentation.create(signOptions, createVpOptions)
    }

    assertTrue(
      exception.message!!.contains("Invalid serialized unsecured/JWS/JWE")
    )
  }

  @Test
  fun `should select matching VcJwts`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val btcAddressVcJwt = buildVcJwt(did = did, signOptions, mapOf("btcAddress" to "btcAddress123"))
    val firstNameVcJwt = buildVcJwt(did = did, signOptions, mapOf("firstName" to "bob"))

    val selectedVcJwts =
      VerifiablePresentation.selectFrom(btcAddressFirstNamePd, listOf(btcAddressVcJwt, firstNameVcJwt))

    assertEquals(2, selectedVcJwts.size)
  }

  @Test
  fun `should return empty list if no matching VcJwts found`() {
    val btcAddressFirstNamePd = buildPresentationDefinition(
      inputDescriptors = listOf(
        buildInputDescriptor(
          fields = listOf(
            buildField(id = "btcAddressId", paths = arrayOf("$.credentialSubject.btcAddress")),
            buildField(id = "firstNameId", paths = arrayOf("$.credentialSubject.firstName"))
          )
        )
      )
    )

    val btcAddressVcJwt = buildVcJwt(did = did, signOptions, mapOf("lightningAddress" to "lightningAddress123"))
    val firstNameVcJwt = buildVcJwt(did = did, signOptions, mapOf("lastName" to "bobby"))

    val selectedVcJwts =
      VerifiablePresentation.selectFrom(btcAddressFirstNamePd, listOf(btcAddressVcJwt, firstNameVcJwt))

    assertEquals(0, selectedVcJwts.size)
  }
}

class SimpleResolver(var didDocument: DIDDocument) : DIDResolver {
  override fun resolve(p0: String?, p1: MutableMap<String, Any>?): ResolveDataModelResult {
    return ResolveDataModelResult.build(null, this.didDocument, null)
  }

  override fun resolveRepresentation(p0: String?, p1: MutableMap<String, Any>?): ResolveRepresentationResult {
    return ResolveRepresentationResult.build()
  }
}

fun buildPresentationDefinition(
  id: String = "test-pd-id",
  name: String = "simple PD",
  purpose: String = "pd for testing",
  inputDescriptors: List<InputDescriptorV2> = listOf()
): PresentationDefinitionV2 {
  return PresentationDefinitionV2(
    id = id,
    name = name,
    purpose = purpose,
    inputDescriptors = inputDescriptors
  )
}

fun buildInputDescriptor(
  id: String = "whatever",
  purpose: String = "id for testing",
  fields: List<FieldV2> = listOf()
): InputDescriptorV2 {
  return InputDescriptorV2(
    id = id,
    purpose = purpose,
    constraints = ConstraintsV2(fields = fields)
  )
}

fun buildField(id: String? = null, vararg paths: String): FieldV2 {
  return FieldV2(id = id, path = paths.toList())
}

fun buildVcJwt(did: String, signOptions: SignOptions, claims: Map<String, Any>): VcJwt {
  val credentialSubject = CredentialSubject.builder()
    .id(URI.create(did))
    .claims(claims.toMutableMap())
    .build()

  val vc: VerifiableCredentialType = VerifiableCredentialType.builder()
    .id(URI.create(UUID.randomUUID().toString()))
    .credentialSubject(credentialSubject)
    .issuer(URI.create(did))
    .issuanceDate(Date())
    .build()

  return VerifiableCredential.create(signOptions, null, vc)
}