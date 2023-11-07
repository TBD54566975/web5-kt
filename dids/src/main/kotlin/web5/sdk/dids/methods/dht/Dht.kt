package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.JWK
import com.turn.ttorrent.bcodec.BEncoder
import org.xbill.DNS.DNSInput
import org.xbill.DNS.Message
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.KeyManager
import java.io.ByteArrayOutputStream
import java.security.SignatureException

public class Dht {
  public companion object {

    /**
     *  Creates a BEP44 Put request according to the BEP44 specification.
     *  https://www.bittorrent.org/beps/bep_0044.html
     *
     *  and the Pkarr specification
     *  https://github.com/Nuhvi/pkarr/blob/main/design/relays.md
     *
     *  Enforces a maximum message size of 1000 bytes and sequence value set to
     *  the current time in milliseconds.
     *
     * @param manager The key manager to use to sign the message [KeyManager].
     * @param keyAlias The alias of an Ed25519 key to sign the message with [JWK].
     * @param message The message to publish (a DNS packet) [Message].
     * @return A BEP44 signed message [Bep44Message].
     * @throws IllegalArgumentException if the private key is not an Ed25519 key.
     * @throws IllegalArgumentException if the message is empty.
     */
    public fun createBep44PutRequest(manager: KeyManager, keyAlias: String, message: Message): Bep44Message {
      // get the public key to verify it is an Ed25519 key
      val pubKey = manager.getPublicKey(keyAlias)
      require(
        pubKey.keyType == Ed25519.keyType &&
          pubKey.algorithm == Ed25519.algorithm
      ) {
        "Must supply an Ed25519 key"
      }

      // set the sequence number to the current time in milliseconds
      val seq = System.currentTimeMillis() / 1000
      val v = message.toWire()
      if (v.isEmpty()) {
        throw IllegalArgumentException("Message must be not be empty")
      }
      return signBep44Message(manager, keyAlias, seq, v)
    }

    /**
     * Parses a BEP44 Get response into a DNS packet according to the BEP44 specification
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * and the Pkarr specification
     * https://github.com/Nuhvi/pkarr/blob/main/design/relays.md
     *
     * @param message The BEP44 message to parse [Bep44Message].
     * @return A DNS packet [Message].
     * @throws IllegalArgumentException if the message is malformed.
     * @throws SignatureException if the signature is invalid.
     */
    public fun parsePkarrGetResponse(message: Bep44Message): Message {
      require(message.v.isNotEmpty() && message.k.size == 32 && message.sig.size == 64) {
        "Malformed Bep44Message"
      }

      // verify message signature
      if (!verifyBep44Message(message)) {
        throw SignatureException("Invalid signature")
      }

      DNSInput(message.v).let { dnsInput ->
        return Message(dnsInput.readByteArray())
      }
    }

    /**
     * Signs a message according to the BEP44 specification.
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * @param manager The key manager to use to sign the message [KeyManager].
     * @param keyAlias The alias of an Ed25519 key to sign the message with [JWK].
     * @param seq The sequence number of the message.
     * @param v The value to be written to the DHT.
     * @return A BEP44 signed message [Bep44Message].
     * @throws IllegalArgumentException if the private key is not an Ed25519 key.
     * @throws IllegalArgumentException if the value to sign is empty.
     * @throws IllegalArgumentException if the length of the compressed v value is > 1000 bytes.
     */
    public fun signBep44Message(manager: KeyManager, keyAlias: String, seq: Long, v: ByteArray): Bep44Message {
      // get the public key to verify it is an Ed25519 key
      val pubKey = manager.getPublicKey(keyAlias)
      require(
        pubKey.keyType == Ed25519.keyType &&
          pubKey.algorithm == Ed25519.algorithm
      ) {
        "Must supply an Ed25519 key"
      }

      // encode v using bencode according to the BEP44 spec
      val bytesToSign = bufferToSign(seq, v)

      // sign and return the BEP44 message
      manager.sign(keyAlias, bytesToSign).let { signature ->
        return Bep44Message(
          v = v,
          k = Ed25519.publicKeyToBytes(pubKey),
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

      // decode v using bencode
      bufferToSign(message.seq, message.v).let { bytesToVerify ->
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

    /**
     * Creates a buffer to sign according to the BEP44 Signature Verification specification.
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * @param seq The sequence number of the message.
     * @param v The value to be bencoded and then sign.
     * @return A buffer to sign [ByteArray].
     * @throws IllegalArgumentException if the value to sign is empty.
     * @throws IllegalArgumentException if the length of the compressed v value is > 1000 bytes.
     */
    private fun bufferToSign(seq: Long, v: ByteArray): ByteArray {
      val out = ByteArrayOutputStream()
      BEncoder.bencode(v, out)
      val vEncoded = out.toString()

      require(vEncoded.toByteArray().size <= 1000) {
        "Value must be <= 1000 bytes commpressed"
      }

      // encode according to BEP44 Signature Verification
      val bufferToSign = ByteArrayOutputStream()
      bufferToSign.write("3:seqi${seq}e1:v${vEncoded}".toByteArray())
      return bufferToSign.toByteArray()
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