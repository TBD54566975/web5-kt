package web5.sdk.dids.methods


/**
 * Utl methods for DIDs.
 *
 */
public object DidUtil {

  /**
   * Parse verification method id into didUrl and fragment.
   *
   * @param verificationMethodId to parse
   * @return SimpleDid containing didUrl and fragment
   */
  public fun parseVerificationMethodId(verificationMethodId: String): SimpleDid {

    val verificationMethodIdArray = verificationMethodId.split("#")
    require(verificationMethodIdArray.size == 2) {
      "Invalid verification method id: $verificationMethodId"
    }
    return SimpleDid(verificationMethodIdArray[0], verificationMethodIdArray[1])
  }

  /**
   * Simple did.
   *
   * @property didUrlString The did url string
   * @property fragment The fragment.
   * @constructor Create empty Simple did
   */
  public class SimpleDid(public val didUrlString: String, public val fragment: String)
}
