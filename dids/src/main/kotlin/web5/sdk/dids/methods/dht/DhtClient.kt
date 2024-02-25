package web5.sdk.dids.methods.dht

import com.nimbusds.jose.jwk.JWK
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.client.statement.readBytes
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import kotlinx.coroutines.runBlocking
import org.xbill.DNS.DNSInput
import org.xbill.DNS.Message
import web5.sdk.common.ZBase32
import web5.sdk.crypto.Ed25519
import web5.sdk.crypto.KeyManager
import web5.sdk.dids.exceptions.PkarrRecordNotFoundException
import web5.sdk.dids.exceptions.PkarrRecordResponseException
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SignatureException

private val colon = ":".toByteArray(charset("UTF-8"))

/**
 * A utility class for working with the BEP44 DHT specification and Pkarr relays.
 */
internal class DhtClient(
  private val gateway: String = "https://diddht.tbddev.org",
  engine: HttpClientEngine = OkHttp.create()
) {

  private val client = HttpClient(engine)

  /**
   * Puts a message to the DHT according to the Pkarr relay specification
   * https://github.com/Nuhvi/pkarr/blob/main/design/relays.md#put
   *
   * @param id The z-base-32 encoded identifier of the message to publish (e.g. a did:dht suffix value) [String].
   * @param message The message to publish (a DNS packet) [Message].
   * @throws IllegalArgumentException if the identifier is not a z-base-32 encoded Ed25519 public key.
   * @throws Exception if the message is not successfully put to the DHT.
   */
  fun pkarrPut(id: String, message: Bep44Message) {
    require(ZBase32.decode(id).size == 32) {
      "Identifier must be a z-base-32 encoded Ed25519 public key"
    }

    // construct a body of the form:
    // 64 bytes sig : 8 bytes u64 big-endian seq : 0-1000 bytes of v.
    val seqBuffer = ByteBuffer.allocate(Long.SIZE_BYTES)
    seqBuffer.order(ByteOrder.BIG_ENDIAN)
    seqBuffer.putLong(message.seq)
    val seqBytes = seqBuffer.array()
    val body = message.sig + seqBytes + message.v

    val response = runBlocking {
      client.put("${gateway}/${id}") {
        contentType(ContentType.Application.OctetStream)
        setBody(body)
      }
    }

    if (!response.status.isSuccess()) {
      val err = runBlocking { response.bodyAsText() }
      throw PkarrRecordResponseException("Error writing Pkarr Record Set for id $id. Error: $err")
    }
  }

  /**
   * Gets a message from the DHT according to the Pkarr relay specification
   * https://github.com/Nuhvi/pkarr/blob/main/design/relays.md#get
   *
   * @param id The z-base-32 encoded identifier of the message to get (e.g. a did:dht suffix value) [String].
   * @return A BEP44 message [Bep44Message].
   * @throws IllegalArgumentException if the identifier is not a z-base-32 encoded Ed25519 public key.
   * @throws PkarrRecordNotFoundException if the record is not found.
   * @throws PkarrRecordResponseException if the response from the dht gateway is not successful.
   */
  @Throws(PkarrRecordResponseException::class, PkarrRecordNotFoundException::class)
  fun pkarrGet(id: String): Bep44Message {
    val publicKey = ZBase32.decode(id)
    require(publicKey.size == 32) {
      "Identifier must be a z-base-32 encoded Ed25519 public key"
    }

    val response = runBlocking { client.get("${gateway}/${id}") }
    if (!response.status.isSuccess()) {
      val err = runBlocking { response.bodyAsText() }
      if (err.contains("pkarr record not found")) {
        throw PkarrRecordNotFoundException()
      }
      throw PkarrRecordResponseException("Error reading Pkarr Record Set of id $id. Error: $err")
    }

    val responseBytes = runBlocking { response.readBytes() }
    require(responseBytes.size >= 72) {
      "Malformed response from DHT"
    }
    val sig = responseBytes.sliceArray(0..63)
    val seq = ByteBuffer.wrap(responseBytes.sliceArray(64..71)).order(ByteOrder.BIG_ENDIAN).long
    val v = responseBytes.sliceArray(72 until responseBytes.size)

    return Bep44Message(v, publicKey, sig, seq)
  }

  companion object {

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
    fun createBep44PutRequest(manager: KeyManager, keyAlias: String, message: Message): Bep44Message {
      // get the public key to verify it is an Ed25519 key
      val pubKey = manager.getPublicKey(keyAlias)
      val curve = pubKey.toJSONObject()["crv"]
      require(curve == Ed25519.curve.name) {
        "Must supply an Ed25519 key"
      }

      // set the sequence number to the current time in seconds
      val seq = System.currentTimeMillis() / 1000
      val v = message.toWire()
      require(!v.isEmpty()) {
        "Message must be not be empty"
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
    fun parseBep44GetResponse(message: Bep44Message): Message {
      // verify message signature
      verifyBep44Message(message)

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
    fun signBep44Message(manager: KeyManager, keyAlias: String, seq: Long, v: ByteArray): Bep44Message {
      // get the public key to verify it is an Ed25519 key
      val pubKey = manager.getPublicKey(keyAlias)

      val curve = pubKey.toJSONObject()["crv"]
      require(curve == Ed25519.curve.name) {
        "Must supply an Ed25519 key"
      }

      // encode v using bencode
      val vEncoded = bencode(v)

      require(vEncoded.size <= 1000) {
        "Value must be <= 1000 bytes compressed, current bytes {${vEncoded.size}}"
      }

      // encode according to BEP44
      val bytesToSign = "3:seqi${seq}e1:v".toByteArray() + vEncoded

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

    /** Encodes a byte array according to https://en.wikipedia.org/wiki/Bencode. */
    internal fun bencode(bs: ByteArray): ByteArray {
      val out = ByteArrayOutputStream()
      val l = bs.size.toString()
      out.write(l.toByteArray(charset("UTF-8")))
      out.write(colon)
      out.write(bs)
      return out.toByteArray()
    }

    /**
     * Verifies a message according to the BEP44 Signature Verification specification.
     * https://www.bittorrent.org/beps/bep_0044.html
     *
     * @param message The message to verify.
     * @return True if the message is verified, false otherwise.
     * @throws IllegalArgumentException if the Bep44Message is malformed.
     * @throws SignatureException if the signature is invalid.
     */
    fun verifyBep44Message(message: Bep44Message) {
      val vEncoded = bencode(message.v)

      // prepare buffer and verify
      val bytesToVerify = "3:seqi${message.seq}e1:v".toByteArray() + vEncoded

      // create a JWK representation of the public key
      val ed25519PublicKey = Ed25519.bytesToPublicKey(message.k)

      // verify the signature
      Ed25519.verify(ed25519PublicKey, bytesToVerify, message.sig)
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
internal data class Bep44Message(
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