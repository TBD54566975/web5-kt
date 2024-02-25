package web5.sdk.dids.didcore

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.DeserializationContext
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.fasterxml.jackson.databind.deser.std.FromStringDeserializer
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import web5.sdk.common.Convert
import web5.sdk.common.EncodingFormat

// todo what the heck are these i brought them over from did ion stuff i deleted

/**
 * Contains metadata about the DID document.
 *
 * @property created Timestamp of when the DID was created.
 * @property updated Timestamp of the last time the DID was updated.
 * @property deactivated Indicates whether the DID has been deactivated. `true` if deactivated, `false` otherwise.
 * @property versionId Specific version of the DID document.
 * @property nextUpdate Timestamp of the next expected update of the DID document.
 * @property nextVersionId The version ID expected for the next version of the DID document.
 * @property equivalentId Alternative ID that can be used interchangeably with the canonical DID.
 * @property canonicalId The canonical ID of the DID as per method-specific rules.
 * @property types Returns types for DIDs that support type indexing.
 */
public class DidDocumentMetadata(
  public var created: String? = null,
  public var updated: String? = null,
  public var deactivated: Boolean? = null,
  public var versionId: String? = null,
  public var nextUpdate: String? = null,
  public var nextVersionId: String? = null,
  public var equivalentId: List<String>? = null,
  public var canonicalId: String? = null,
  public val method: MetadataMethod? = null,
  public val types: List<Int>? = null
)

/**
 * Metadata about the did method as defined in bullet 3 (subitem 'method') of https://identity.foundation/sidetree/spec/#did-resolver-output
 */
public class MetadataMethod(
  public val published: Boolean,
  public val recoveryCommitment: Commitment,
  public val updateCommitment: Commitment,
)


/**
 * Represents the commitment value as defined in item 3 of https://identity.foundation/sidetree/spec/#public-key-commitment-scheme.
 */
@JsonSerialize(using = CommitmentSerializer::class)
@JsonDeserialize(using = CommitmentDeserializer::class)
public class Commitment(public override val bytes: ByteArray) : BytesField


private class CommitmentSerializer : StdSerializer<Commitment>(Commitment::class.java) {
  override fun serialize(value: Commitment?, gen: JsonGenerator, provider: SerializerProvider?) {
    with(gen) {
      writeString(value?.toBase64Url())
    }
  }
}

private class CommitmentDeserializer : FromStringDeserializer<Commitment>(Commitment::class.java) {
  override fun _deserialize(value: String?, ctxt: DeserializationContext?): Commitment {
    return Commitment(Convert(value, EncodingFormat.Base64Url).toByteArray())
  }
}


internal interface BytesField {
  val bytes: ByteArray

  fun toBase64Url(): String {
    return Convert(bytes).toBase64Url(padding = false)
  }
}

private class RevealDeserializer : FromStringDeserializer<Reveal>(
  Reveal::class.java
) {
  override fun _deserialize(value: String?, ctxt: DeserializationContext?): Reveal {
    return Reveal(Convert(value, EncodingFormat.Base64Url).toByteArray())
  }
}


/**
 * Represents the reveal value as defined in item 3 of https://identity.foundation/sidetree/spec/#public-key-commitment-scheme.
 */
@JsonSerialize(using = RevealSerializer::class)
@JsonDeserialize(using = RevealDeserializer::class)
public class Reveal(public override val bytes: ByteArray) : BytesField

private class RevealSerializer : StdSerializer<Reveal>(Reveal::class.java) {
  override fun serialize(value: Reveal?, gen: JsonGenerator, provider: SerializerProvider?) {
    with(gen) {
      writeString(value?.toBase64Url())
    }
  }
}
