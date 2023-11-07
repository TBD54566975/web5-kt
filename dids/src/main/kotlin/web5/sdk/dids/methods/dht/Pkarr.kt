package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.JWK
import com.turn.ttorrent.bcodec.BEncoder
import org.xbill.DNS.Message
import web5.sdk.crypto.Ed25519
import java.io.ByteArrayOutputStream

public class Pkarr {
  public companion object {
    public fun createPkarrPutRequest(ed25519PrivateKey: JWK, message: Message): Bep44Message {
      require(
        ed25519PrivateKey.isPrivate &&
          ed25519PrivateKey.keyType == Ed25519.keyType &&
          ed25519PrivateKey.algorithm == Ed25519.algorithm
      ) {
        "Must supply an Ed25519 private key"
      }
      require(message.numBytes() > 0) {
        "Message must be non-empty"
      }
      throw NotImplementedError()
    }

    /**
     * Signs a message according to the BEP44 Signature Verification specification.
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * @param ed25519PrivateKey The private key to sign the message with.
     * @param seq The sequence number of the message.
     * @param v The bencoded value to sign.
     * @return A BEP44 signed message.
     * @throws IllegalArgumentException if the private key is not an Ed25519 key.
     * @throws IllegalArgumentException if the value to sign is empty.
     */
    @OptIn(ExperimentalStdlibApi::class)
    public fun signBep44Message(ed25519PrivateKey: JWK, seq: Long, v: ByteArray): Bep44Message {
      require(
        ed25519PrivateKey.isPrivate &&
          ed25519PrivateKey.keyType == Ed25519.keyType &&
          ed25519PrivateKey.algorithm == Ed25519.algorithm
      ) {
        "Must supply an Ed25519 private key"
      }

      // encode v using bencode
      val out = ByteArrayOutputStream()
      BEncoder.bencode(v, out)
      val vEncoded = out.toString()

      // encode according to BEP44 Signature Verification
      val bufferToSign = ByteArrayOutputStream()
      bufferToSign.write("3:seqi${seq}e1:v${vEncoded}".toByteArray())
      val bytesToSign = bufferToSign.toByteArray()

      // sign and return the BEP44 message
      Ed25519.sign(ed25519PrivateKey, bytesToSign).let { signature ->
        return Bep44Message(
          v = v,
          k = Ed25519.publicKeyToBytes(ed25519PrivateKey.toPublicJWK()),
          sig = signature,
          seq = seq
        )
      }
    }

    /**
     * Verifies a message according to the BEP44 Signature Verification specification.
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * @param message The message to verify.
     * @return True if the message is verified, false otherwise.
     * @throws IllegalArgumentException if the Bep44Message is malformed.
     */
    public fun verifyBep44Message(message: Bep44Message): Boolean {
      require(message.v.isNotEmpty() && message.k.size == 32 && message.sig.size == 64) {
        "Malformed Bep44Message"
      }

      // encode v using bencode
      val out = ByteArrayOutputStream()
      BEncoder.bencode(message.v, out)
      val vEncoded = out.toString()

      // encode the message according to BEP44 Signature Verification
      val bufferToVerify = ByteArrayOutputStream()
      bufferToVerify.write("3:seqi${message.seq}e1:v".toByteArray())
      bufferToVerify.write(vEncoded.toByteArray())
      val bytesToVerify = bufferToVerify.toByteArray()

      // create a JWK representation of the public key
      val ed25519PublicKey = Ed25519.bytesToPublicKey(message.k)

      // verify the signature
      try {
        Ed25519.verify(ed25519PublicKey, bytesToVerify, message.sig)
      } catch (e: Exception) {
        return false
      }
      return true
    }
  }
}

/**
 * Complies with BEP-44 https://www.bittorrent.org/beps/bep_0044.html
 * Implements a subset of BEP-44 for Mutable Items that omits salt and CAS values.
 *
 * @property v The value to publish.
 * @property k The 32 byte representation of an Ed25519 key to publish the value under.
 * @property sig The 64 byte EdDSA signature over the value and sequence number.
 * @property seq The sequence number of the message.
 */
public data class Bep44Message(
  val v: ByteArray,
  val k: ByteArray,
  val sig: ByteArray,
  val seq: Long
) {
  init {
    require(v.isNotEmpty()) { "Value must be non-empty" }
    require(k.size == 32) { "Key must be 32 bytes" }
    require(sig.size == 64) { "Signature must be 64 bytes" }
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as Bep44Message

    if (!v.contentEquals(other.v)) return false
    if (!k.contentEquals(other.k)) return false
    if (!sig.contentEquals(other.sig)) return false
    if (seq != other.seq) return false

    return true
  }

  override fun hashCode(): Int {
    var result = v.hashCode()
    result = 31 * result + k.contentHashCode()
    result = 31 * result + sig.contentHashCode()
    result = 31 * result + seq.hashCode()
    return result
  }
}