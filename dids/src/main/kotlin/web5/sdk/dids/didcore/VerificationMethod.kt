package web5.sdk.dids.didcore

import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import web5.sdk.crypto.jwk.Jwk
import web5.sdk.dids.JwkSerializer
import web5.sdk.dids.JwkDeserializer

/**
 * VerificationMethod expresses verification methods, such as cryptographic
 * public keys, which can be used to authenticate or authorize interactions
 * with the DID subject or associated parties.
 * For example, a cryptographic public key can be used as a verification method with
 * respect to a digital signature; in such usage, it verifies that the
 * signer could use the associated cryptographic private key.
 * Specification Reference: https://www.w3.org/TR/did-core/#verification-methods
 *
 * @property id id of the VerificationMethod
 * @property type references exactly one verification method type. In order to maximize global
 *  	            interoperability, the verification method type SHOULD be registered in the
 *                DID Specification Registries: https://www.w3.org/TR/did-spec-registries/
 * @property controller a value that conforms to the rules in DID Syntax: https://www.w3.org/TR/did-core/#did-syntax
 * @property publicKeyJwk specification reference: https://www.w3.org/TR/did-core/#dfn-publickeyjwk
 */
public class VerificationMethod(
  public val id: String,
  public val type: String,
  public val controller: String,
  @JsonSerialize(using = JwkSerializer::class)
  @JsonDeserialize(using = JwkDeserializer::class)
  public val publicKeyJwk: Jwk? = null
) {
  /**
   * Checks type of VerificationMethod.
   *
   * @param type The type to check
   * @return true/false if the type matches
   */
  public fun isType(type: String): Boolean {
    return type == this.type
  }

  override fun toString(): String {
    return "VerificationMethod(" +
      "id='$id', " +
      "type='$type', " +
      "controller='$controller', " +
      "publicKeyJwk=$publicKeyJwk)"
  }

  /**
   * Builder object to build a VerificationMethod.
   */
  public class Builder {
    private var id: String? = null
    private var type: String? = null
    private var controller: String? = null
    private var publicKeyJwk: Jwk? = null


    /**
     * Adds id to the VerificationMethod.
     *
     * @param id of the VerificationMethod
     * @return Builder object
     */
    public fun id(id: String): Builder = apply { this.id = id }

    /**
     * Adds type to the VerificationMethod.
     *
     * @param type of the VerificationMethod
     * @return Builder object
     */
    public fun type(type: String): Builder = apply { this.type = type }

    /**
     * Adds controller to the VerificationMethod.
     *
     * @param controller of the VerificationMethod
     * @return Builder object
     */
    public fun controller(controller: String): Builder = apply { this.controller = controller }

    /**
     * Adds public key jwk to the VerificationMethod.
     *
     * @param publicKeyJwk of the VerificationMethod
     * @return Builder object
     */
    public fun publicKeyJwk(publicKeyJwk: Jwk): Builder = apply { this.publicKeyJwk = publicKeyJwk }


    /**
     * Builds VerificationMethod after validating the required fields.
     *
     * @return VerificationMethod
     */
    public fun build(): VerificationMethod {
      check(id != null) { "ID is required" }
      check(type != null) { "Type is required" }
      check(controller != null) { "Controller is required" }
      check(publicKeyJwk != null) { "PublicKeyJwk is required" }
      return VerificationMethod(id!!, type!!, controller!!, publicKeyJwk!!)
    }

  }
}
