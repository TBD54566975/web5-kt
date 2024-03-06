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
 * @see [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/)
 */
public class BitstringStatusListEntry(
  public val id: URI,
  public val type: String,
  public val statusListIndex: String,
  public val statusListCredential: URI,
  public val statusPurpose: String,
) {
  /**
   * Builder class for creating [BitstringStatusListEntry] instances.
   */
  public class Builder {
    private lateinit var id: URI
    private var type: String = DEFAULT_BITSTRING_STATUS_LIST_ENTRY_TYPE
    private lateinit var statusListIndex: String
    private lateinit var statusListCredential: URI
    private lateinit var statusPurpose: String

    /**
     * Sets the ID for the bitstring status list entry.
     * @param id The unique identifier of the bitstring status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the type for the bitstring status list entry.
     * @param type The type of the bitstring status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun type(type: String): Builder = apply { this.type = type }

    /**
     * Sets the status list index for the bitstring status list entry.
     * @param statusListIndex The status list index of the bitstring status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusListIndex(statusListIndex: String): Builder = apply { this.statusListIndex = statusListIndex }

    /**
     * Sets the status list credential for the bitstring status list entry.
     * @param statusListCredential The status list credential of the bitstring status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusListCredential(statusListCredential: URI): Builder =
      apply { this.statusListCredential = statusListCredential }

    /**
     * Sets the status purpose for the bitstring status list entry.
     * @param statusPurpose The status purpose of the bitstring status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusPurpose(statusPurpose: String): Builder = apply { this.statusPurpose = statusPurpose }

    /**
     * Builds and returns the [BitstringStatusListEntry] object.
     * @return The constructed [BitstringStatusListEntry] object.
     * @throws IllegalStateException If any required fields are not set.
     */
    public fun build(): BitstringStatusListEntry {
      require(id.toString().isNotBlank()) { "Id cannot be blank" }
      require(statusListIndex.isNotBlank()) { "StatusListIndex cannot be blank" }
      require(statusListCredential.toString().isNotBlank()) { "StatusListCredential cannot be blank" }
      require(statusPurpose.isNotBlank()) { "StatusPurpose cannot be blank" }

      return BitstringStatusListEntry(
        id = id,
        type = type,
        statusListIndex = statusListIndex,
        statusListCredential = statusListCredential,
        statusPurpose = statusPurpose
      )
    }
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