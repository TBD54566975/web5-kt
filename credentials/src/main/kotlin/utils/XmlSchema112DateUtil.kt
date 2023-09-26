package web5.credentials.utils

import java.text.ParseException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.TimeZone

public object Util {
  /**
   * Retrieves the current timestamp in XML Schema 1.1.2 date-time format.
   *
   * This function returns a date-time string in the format "yyyy-MM-ddTHH:mm:ssZ" without milliseconds.
   *
   * @return The current timestamp in XML Schema 1.1.2 format.
   */
  public fun getCurrentXmlSchema112Timestamp(): String {
    val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.timeZone = TimeZone.getTimeZone("UTC")
    return sdf.format(Date())
  }

  /**
   * Converts a given Date object into XML Schema 1.1.2 date-time format.
   *
   * This function returns a date-time string in the format "yyyy-MM-ddTHH:mm:ssZ" without milliseconds.
   *
   * @param date The Date object to be converted.
   * @return The formatted timestamp in XML Schema 1.1.2 format.
   */
  public fun getXmlSchema112Timestamp(date: Date): String {
    val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.timeZone = TimeZone.getTimeZone("UTC")
    return sdf.format(date)
  }

  /**
   * Validates a timestamp string against the XML Schema 1.1.2 date-time format.
   *
   * This function checks whether the provided timestamp string conforms to the
   * format "yyyy-MM-ddTHH:mm:ssZ", without milliseconds, as defined in XML Schema 1.1.2.
   *
   * @param timestamp The timestamp string to validate.
   * @return `true` if the timestamp is valid, `false` otherwise.
   */
  public fun isValidXmlSchema112Timestamp(timestamp: String): Boolean {
    val sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.isLenient = false // This ensures strict date format matching

    return try {
      sdf.parse(timestamp)
      true
    } catch (e: ParseException) {
      false
    }
  }
}