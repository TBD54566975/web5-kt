package web5.crypto

import Convert
import asBase64Url

public fun main() {
  val base64urlEncodedStr = Convert("hi").toBase64Url()
  println(base64urlEncodedStr)

  val str = Convert(base64urlEncodedStr).asBase64Url().toStr()
  println(str)

  val encodedAgane = Convert(str).toBase64Url()
  println(encodedAgane)
}