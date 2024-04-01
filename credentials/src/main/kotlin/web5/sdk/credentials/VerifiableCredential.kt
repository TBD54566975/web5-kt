package web5.sdk.credentials

import com.danubetech.verifiablecredentials.CredentialSubject
import com.danubetech.verifiablecredentials.credentialstatus.CredentialStatus
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.convertValue
import com.nfeld.jsonpathkt.JsonPath
import com.nfeld.jsonpathkt.extension.read
import web5.sdk.common.Json
import web5.sdk.dids.did.BearerDid
import web5.sdk.jose.jwt.Jwt
import web5.sdk.jose.jwt.JwtClaimsSet
import java.net.URI
import java.security.SignatureException
import java.util.Date
import java.util.UUID

/**
 * Type alias representing the danubetech Verifiable Credential data model.
 * This typealias simplifies the use of the [com.danubetech.verifiablecredentials.VerifiableCredential] class.
 */
public typealias VcDataModel = com.danubetech.verifiablecredentials.VerifiableCredential

/**
 * `VerifiableCredential` represents a digitally verifiable credential according to the
 * [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/).
 *
 * It provides functionalities to sign, verify, and create credentials, offering a concise API to
 * work with JWT representations of verifiable credentials and ensuring that the signatures
 * and claims within those JWTs can be validated.
 *
 * @property vcDataModel The [VcDataModel] instance representing the core data model of a verifiable credential.
 */
public class VerifiableCredential internal constructor(public val vcDataModel: VcDataModel) {

  public val type: String
    get() = vcDataModel.types.last()
  public val issuer: String
    get() = vcDataModel.issuer.toString()

  public val subject: String
    get() = vcDataModel.credentialSubject.id.toString()
  public val evidence: List<Any>?
    get() = vcDataModel.toMap().get("evidence") as List<Any>?

  /**
   * Sign a verifiable credential using a specified decentralized identifier ([did]) with the private key that pairs
   * with the public key identified by [assertionMethodId].
   *
   * If the [assertionMethodId] is null, the function will attempt to use the first available verification method from
   * the [did]. The result is a String in a JWT format.
   *
   * @param did The [BearerDid] used to sign the credential.
   * @param assertionMethodId An optional identifier for the assertion method that will be used for verification of the
   *        produced signature.
   * @return The JWT representing the signed verifiable credential.
   *
   * Example:
   * ```
   * val signedVc = verifiableCredential.sign(myDid)
   * ```
   */
  @JvmOverloads
  public fun sign(did: BearerDid, assertionMethodId: String? = null): String {
    val payload = JwtClaimsSet.Builder()
      .issuer(did.uri)
      .issueTime(vcDataModel.issuanceDate.time)
      .subject(vcDataModel.credentialSubject.id.toString())
      .misc("vc", vcDataModel.toMap())
      .build()

    return Jwt.sign(did, payload)
  }

  /**
   * Retrieves a field from a verifiable credential by its JSON path.
   *
   * @param path The JSON path to the desired field.
   * @return The field's value if found, or null if the field is not present.
   */
  public fun getFieldByJsonPath(path: String): String? {
    val vcJsonString: String = this.vcDataModel.toJson()
    return JsonPath.parse(vcJsonString)?.read<String>(path)
  }

  /**
   * Converts the current object to its JSON representation.
   *
   * @return The JSON representation of the object.
   */
  override fun toString(): String {
    return vcDataModel.toJson()
  }

  public companion object {
    private val objectMapper: ObjectMapper = ObjectMapper().apply {
      registerModule(KotlinModule.Builder().build())
      setSerializationInclusion(JsonInclude.Include.NON_NULL)
    }

    /**
     * Create a [VerifiableCredential] based on the provided parameters.
     *
     * @param type The type of the credential, as a [String].
     * @param issuer The issuer URI of the credential, as a [String].
     * @param subject The subject URI of the credential, as a [String].
     * @param data The credential data, as a generic type [T].
     * @param issuanceDate Optional date to set in the `issuanceDate` property of the credential.
     * @param expirationDate Optional date to set in the `expirationDate` property of the credential.
     * @param evidence Optional evidence property that gives additional supporting data
     * @return A [VerifiableCredential] instance.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.create("ExampleCredential", "http://example.com/issuers/1", "http://example.com/subjects/1", myData)
     * ```
     */
    @JvmOverloads
    public fun <T> create(
      type: String,
      issuer: String,
      subject: String,
      data: T,
      credentialStatus: CredentialStatus? = null,
      issuanceDate: Date = Date(),
      expirationDate: Date? = null,
      evidence: List<Any>? = null
    ): VerifiableCredential {

      val jsonData: JsonNode = objectMapper.valueToTree(data)
      val mapData: Map<String, Any> = when (jsonData.isObject) {
        true -> objectMapper.convertValue<Map<String, Any>>(jsonData)
        false -> throw IllegalArgumentException("expected data to be parseable into a JSON object")
      }

      val credentialSubject = CredentialSubject.builder()
        .id(URI.create(subject))
        .claims(mapData)
        .build()

      val vcDataModel = VcDataModel.builder()
        .type(type)
        .id(URI.create("urn:uuid:${UUID.randomUUID()}"))
        .issuer(URI.create(issuer))
        .issuanceDate(issuanceDate)
        .credentialSubject(credentialSubject)
        .apply { expirationDate?.let { expirationDate(it) } }
        .apply {
          evidence?.let {
            properties(
              mapOf(
                "evidence" to evidence
              ) as Map<String, Any>?
            )
          }
        }
        .apply {
          credentialStatus?.let {
            credentialStatus(it)
            context(URI.create("https://w3id.org/vc/status-list/2021/v1"))
          }
        }
        .build()

      // This should be a no-op just to make sure we've set all the correct fields.
      validateDataModel(vcDataModel.toMap())

      return VerifiableCredential(vcDataModel)
    }

    /**
     * Verifies the integrity and authenticity of a Verifiable Credential (VC) encoded as a JSON Web Token (JWT).
     *
     * This method conforms to wording about VC data model JWT encoding
     * https://www.w3.org/TR/vc-data-model/#jwt-encoding
     *
     * If any of these steps fail, the function will throw a [IllegalArgumentException]
     * with a message indicating the nature of the failure:
     * - exp MUST represent the expirationDate property, encoded as a UNIX timestamp (NumericDate).
     * - iss MUST represent the issuer property of a verifiable credential or the holder property
     *   of a verifiable presentation.
     * - nbf MUST represent issuanceDate, encoded as a UNIX timestamp (NumericDate).
     * - jti MUST represent the id property of the verifiable credential or verifiable presentation.
     * - sub MUST represent the id property contained in the credentialSubject.
     *
     * @param vcJwt The Verifiable Credential in JWT format as a [String].
     * @throws IllegalArgumentException if the verification fails at any step, providing a message with failure details.
     *
     * ### Example:
     * ```
     * try {
     *     VerifiableCredential.verify(signedVcJwt)
     *     println("VC Verification successful!")
     * } catch (e: SignatureException) {
     *     println("VC Verification failed: ${e.message}")
     * }
     * ```
     */
    public fun verify(vcJwt: String) {
      val decodedJwt = Jwt.decode(vcJwt)

      val exp = decodedJwt.claims.exp
      val iss =  decodedJwt.claims.iss
      val nbf =  decodedJwt.claims.nbf
      val jti =  decodedJwt.claims.jti
      val sub =  decodedJwt.claims.sub
      val vc = parseJwt(vcJwt)
      val vcTyped = vc.vcDataModel

      // exp MUST represent the expirationDate property, encoded as a UNIX timestamp (NumericDate).
      require(exp == null || vcTyped.expirationDate == null || exp == vcTyped.expirationDate.time / 1000) {
        "Verification failed: exp claim does not match expirationDate"
      }

      require(iss != null) { "Verification failed: iss claim is required" }

      // iss MUST represent the issuer property of a verifiable credential or the holder property of a verifiable presentation.
      require(iss == vcTyped.issuer.toString()) {
        "Verification failed: iss claim does not match expected issuer"
      }

      // nbf cannot represent time in the future
      require(nbf == null || nbf <= Date().time / 1000) {
        "Verification failed: nbf claim is in the future"
      }

      // nbf MUST represent issuanceDate, encoded as a UNIX timestamp (NumericDate).
      require(nbf == null || vcTyped.issuanceDate == null || nbf == vcTyped.issuanceDate.time / 1000) {
        "Verification failed: nbf claim does not match issuanceDate"
      }

      // sub MUST represent the id property contained in the credentialSubject.
      require(sub == null || sub == vcTyped.credentialSubject.id.toString()) {
        "Verification failed: sub claim does not match credentialSubject.id"
      }

      // jti MUST represent the id property of the verifiable credential or verifiable presentation.
      require(jti == null || jti == vcTyped.id.toString()) {
        "Verification failed: jti claim does not match id"
      }

      validateDataModel(vcTyped.toMap())
      decodedJwt.verify()
    }

    /**
     * Parses a JWT into a [VerifiableCredential] instance.
     *
     * @param vcJwt The verifiable credential JWT as a [String].
     * @return A [VerifiableCredential] instance derived from the JWT.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.parseJwt(signedVcJwt)
     * ```
     */
    public fun parseJwt(vcJwt: String): VerifiableCredential {
      val jwt = Jwt.decode(vcJwt)
      val jwtPayload = jwt.claims
      val vcDataModelValue = jwtPayload.misc["vc"] ?:
        throw IllegalArgumentException("jwt payload missing vc property")

      val vcDataModelMap = Json.parse<Map<String, Any>>(Json.stringify(vcDataModelValue))

      val vcDataModel = VcDataModel.fromMap(vcDataModelMap)

      return VerifiableCredential(vcDataModel)
    }

    /**
     * Parses a JSON string into a [VerifiableCredential] instance.
     *
     * @param vcJson The verifiable credential JSON as a [String].
     * @return A [VerifiableCredential] instance derived from the JSON.
     * @throws IllegalArgumentException if the credential within [vcJson] does not conform to the W3C Verifiable
     *   Credential Data Model 1.1 as specified in https://www.w3.org/TR/vc-data-model/.
     *
     * Example:
     * ```
     * val vc = VerifiableCredential.fromJson(vcJsonString)
     * ```
     */
    @Throws(IllegalArgumentException::class)
    public fun fromJson(vcJson: String): VerifiableCredential {
      val typeRef = object : TypeReference<HashMap<String, Any>>() {}
      val vcMap = objectMapper.readValue(vcJson, typeRef)
      validateDataModel(vcMap)
      return VerifiableCredential(VcDataModel.fromMap(vcMap))
    }

    /**
     * Throws an [IllegalArgumentException] if the provided [model] does not conform to the W3C Verifiable Credentials
     * Data Model 1.1 as specified in https://www.w3.org/TR/vc-data-model/.
     */
    private fun validateDataModel(model: Map<String, Any>) {
      require(model["credentialSubject"] != null) {
        "credentialSubject property is required"
      }
      val context = model["@context"]
      require(context is List<*> && context.isNotEmpty()) {
        "context must have at least one entry but got $context"
      }

      require(context.first().toString() == "https://www.w3.org/2018/credentials/v1") {
        "first item of context must be https://www.w3.org/2018/credentials/v1"
      }

      val uriRegex = Regex("\\w+:(/?/?)\\S+")

      val id = model["id"]
      if (id != null) {
        require(id is String) {
          "id must be a string but found $id"
        }
        require(uriRegex.matches(id)) {
          "id must be a URI but found $id"
        }
      }

      val type = model["type"]
      require(type is List<*> && type.isNotEmpty()) {
        "type property must have one or more URIs"
      }
      require("VerifiableCredential" == type.first()) {
        "first item of type must be \"VerifiableCredential\""
      }

      val issuanceDate = model["issuanceDate"]

      @Suppress("MaxLineLength")
      val dateTimeLexicalRegex =
        "-?([1-9][0-9]{3,}|0[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\\.[0-9]+)?|(24:00:00(\\.0+)?))(Z|([+\\-])((0[0-9]|1[0-3]):[0-5][0-9]|14:00))?".toRegex()
      require(issuanceDate != null) {
        "issuanceDate property is required"
      }

      require(issuanceDate is String && dateTimeLexicalRegex.matches(issuanceDate)) {
        "issuanceDate must be in XMLSCHEMA11-2 combined date-time format. For example: 2010-01-01T19:23:24Z"
      }

      val issuer = model["issuer"]
      require(issuer != null) {
        "issuer property is required"
      }

      require(issuer !is List<*>) {
        "issuer cannot be a list"
      }

      when (issuer) {
        is String -> {
          require(uriRegex.matches(issuer)) {
            "when issuer is a string, it must be a URI but was $issuer"
          }
        }

        is Map<*, *> -> {
          require(issuer.containsValue("id")) {
            "when issuer is an object, it must contain an id property"
          }
        }

        else ->
          throw IllegalArgumentException(
            "issuer must be a URI or an object containing an id property, but found $issuer"
          )

      }

      val expirationDate = model["expirationDate"]
      if (expirationDate != null) {
        require(expirationDate is String && dateTimeLexicalRegex.matches(expirationDate)) {
          "expirationDate must be in XMLSCHEMA11-2 combined date-time format. For example: 2010-01-01T19:23:24Z"
        }
      }

      val credentialStatus = model["credentialStatus"]
      if (credentialStatus != null) {
        require(credentialStatus is Map<*, *>) {
          "credentialStatus must be an object but found $credentialStatus"
        }

        require(credentialStatus.contains("type")) {
          "credentialStatus must contain a type property"
        }

        require(credentialStatus.contains("id")) {
          "credentialStatus must contain an id property"
        }
      }
    }
  }
}