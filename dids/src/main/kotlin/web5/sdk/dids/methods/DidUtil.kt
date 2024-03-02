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
    return SimpleDid(
      didUriString = verificationMethodIdArray[0],
      fragment = verificationMethodIdArray[1],
      didUrlString = verificationMethodId)
  }

  /**
   * Simple did.
   *
   * @property didUriString The did uri string
   * @property fragment The fragment.
   * @property didUrlString The did url string, in the format of didUriString#fragment`
   * @constructor Create empty Simple did
   */
  public class SimpleDid(public val didUriString: String, public val fragment: String, public val didUrlString: String)
}
