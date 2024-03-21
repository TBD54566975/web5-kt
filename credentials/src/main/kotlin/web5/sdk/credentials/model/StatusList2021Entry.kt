package web5.sdk.credentials.model

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.net.URI

public const val DEFAULT_STATUS_LIST_2021_VC_TYPE: String = "StatusList2021"
public const val DEFAULT_STATUS_LIST_2021_ENTRY_TYPE: String = "StatusList2021Entry"
public const val DEFAULT_STATUS_LIST_CONTEXT: String = "https://w3id.org/vc/status-list/2021/v1"
private fun getObjectMapper(): ObjectMapper = jacksonObjectMapper().apply {
  registerKotlinModule()
  setSerializationInclusion(JsonInclude.Include.NON_NULL)
}

/**
 * The [StatusList2021Entry] instance representing the core data model of a bitstring status list entry.
 *
 * @see [Credential Status List](https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/)
 */
public class StatusList2021Entry(
  public val id: URI,
  public val type: String,
  public val statusListIndex: String,
  public val statusListCredential: URI,
  public val statusPurpose: String,
) {
  /**
   * Builder class for creating [StatusList2021Entry] instances.
   */
  public class Builder {
    private lateinit var id: URI
    private var type: String = DEFAULT_STATUS_LIST_2021_ENTRY_TYPE
    private lateinit var statusListIndex: String
    private lateinit var statusListCredential: URI
    private lateinit var statusPurpose: String

    /**
     * Sets the ID for the credential status list entry.
     * @param id The unique identifier of the credential status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun id(id: URI): Builder = apply { this.id = id }

    /**
     * Sets the type for the credential status list entry.
     * @param type The type of the credential status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun type(type: String): Builder = apply { this.type = type }

    /**
     * Sets the status list index for the credential status list entry.
     * @param statusListIndex The status list index of the credential status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusListIndex(statusListIndex: String): Builder = apply { this.statusListIndex = statusListIndex }

    /**
     * Sets the status list credential for the credential status list entry.
     * @param statusListCredential The status list credential of the credential status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusListCredential(statusListCredential: URI): Builder =
      apply { this.statusListCredential = statusListCredential }

    /**
     * Sets the status purpose for the credential status list entry.
     * @param statusPurpose The status purpose of the credential status list entry.
     * @return Returns this builder to allow for chaining.
     */
    public fun statusPurpose(statusPurpose: String): Builder = apply { this.statusPurpose = statusPurpose }

    /**
     * Builds and returns the [StatusList2021Entry] object.
     * @return The constructed [StatusList2021Entry] object.
     * @throws IllegalStateException If any required fields are not set.
     */
    public fun build(): StatusList2021Entry {
      require(id.toString().isNotBlank()) { "Id cannot be blank" }
      require(statusListIndex.isNotBlank()) { "StatusListIndex cannot be blank" }
      require(statusListCredential.toString().isNotBlank()) { "StatusListCredential cannot be blank" }
      require(statusPurpose.isNotBlank()) { "StatusPurpose cannot be blank" }

      return StatusList2021Entry(
        id = id,
        type = type,
        statusListIndex = statusListIndex,
        statusListCredential = statusListCredential,
        statusPurpose = statusPurpose
      )
    }
  }

  /**
   * Converts the [StatusList2021Entry] instance to a JSON string.
   *
   * @return A JSON string representation of the [StatusList2021Entry] instance.
   */
  public fun toJson(): String = getObjectMapper().writeValueAsString(this)

  /**
   * Converts the [StatusList2021Entry] instance into a Map representation.
   *
   * @return A Map containing key-value pairs representing the properties of the [StatusList2021Entry] instance.
   */
  public fun toMap(): Map<String, Any> =
    getObjectMapper().readValue(this.toJson(), object : TypeReference<Map<String, Any>>() {})

  public companion object {
    /**
     * Parses a JSON string to create an instance of [StatusList2021Entry].
     *
     * @param jsonString The JSON string representation of a [StatusList2021Entry].
     * @return An instance of [StatusList2021Entry].
     */
    public fun fromJsonObject(jsonString: String): StatusList2021Entry =
      getObjectMapper().readValue(jsonString, StatusList2021Entry::class.java)

    /**
     * Creates an instance of [StatusList2021Entry] from a map of its properties.
     *
     * @param map A map containing the properties of a [StatusList2021Entry].
     * @return An instance of [StatusList2021Entry].
     * @throws IllegalArgumentException If required properties are missing.
     */
    public fun fromMap(map: Map<String, Any>): StatusList2021Entry {
      val json = getObjectMapper().writeValueAsString(map)
      return getObjectMapper().readValue(json, StatusList2021Entry::class.java)
    }
  }
}