package web5.sdk.dids.methods


public object DidUtil {
  public fun parseVerificationMethodId(verificationMethodId: String): SimpleDid {

    val verificationMethodIdArray = verificationMethodId.split("#")
    require(verificationMethodIdArray.size == 2) {
      "Invalid verification method id: $verificationMethodId"
    }
    return SimpleDid(verificationMethodIdArray[0], verificationMethodIdArray[1])
  }

  public class SimpleDid(public val didUrlString: String, public val fragment: String)
}
