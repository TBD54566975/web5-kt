package web5.sdk.credentials.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.net.URI

public const val DEFAULT_BITSTRING_STATUS_LIST_VC_TYPE: String = "BitstringStatusListCredential"
public const val DEFAULT_BITSTRING_STATUS_LIST_ENTRY_TYPE: String = "BitstringStatusListEntry"
public const val DEFAULT_STATUS_LIST_CONTEXT: String = "https://w3id.org/vc/status-list/2021/v1"
private fun getObjectMapper(): ObjectMapper = jacksonObjectMapper().apply {
  registerKotlinModule()
  setSerializationInclusion(JsonInclude.Include.NON_NULL)
}

/**
 * The [BitstringStatusListEntry] instance representing the core data model of a bitstring status list entry.
 *
 * @see {@link https://www.w3.org/TR/vc-bitstring-status-list/ | Bitstring Status List }
 */
public class BitstringStatusListEntry(
  public val id: URI,
  public val type: String = DEFAULT_BITSTRING_STATUS_LIST_ENTRY_TYPE,
  public val statusListIndex: String,
  public val statusListCredential: URI,
  public val statusPurpose: String,
) {

  init {
    require( id.toString().isNotBlank()) { "Id cannot be blank" }
    require( statusListIndex.isNotBlank()) { "StatusListIndex cannot be blank" }
    require( statusListCredential.toString().isNotBlank()) { "StatusListCredential cannot be blank" }
    require( statusPurpose.isNotBlank()) { "StatusPurpose cannot be blank" }
  }

  /**
   * Converts the [BitstringStatusListEntry] instance to a JSON string.
   *
   * @return A JSON string representation of the [BitstringStatusListEntry] instance.
   */
  public fun toJson(): String = getObjectMapper().writeValueAsString(this)

  /**
   * Converts the [BitstringStatusListEntry] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [BitstringStatusListEntry] instance.
   */
  public fun toMap(): Map<String, Any> =
    getObjectMapper().readValue(this.toJson(), object : TypeReference<Map<String, Any>>() {})

  public companion object {
    /**
     * Parses a JSON string to create an instance of [BitstringStatusListEntry].
     *
     * @param jsonString The JSON string representation of a [BitstringStatusListEntry].
     * @return An instance of [BitstringStatusListEntry].
     */
    public fun fromJsonObject(jsonString: String): BitstringStatusListEntry =
      getObjectMapper().readValue(jsonString, BitstringStatusListEntry::class.java)

    /**
     * Creates an instance of [BitstringStatusListEntry] from a map of its properties.
     *
     * @param map A map containing the properties of a [BitstringStatusListEntry].
     * @return An instance of [BitstringStatusListEntry].
     * @throws IllegalArgumentException If required properties are missing.
     */
    public fun fromMap(map: Map<String, Any>): BitstringStatusListEntry {
      val json = getObjectMapper().writeValueAsString(map)
      return getObjectMapper().readValue(json, BitstringStatusListEntry::class.java)
    }
  }
}