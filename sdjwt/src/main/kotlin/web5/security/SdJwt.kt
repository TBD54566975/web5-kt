package web5.security

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject.State
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

private const val separator = "~"

/**
 * Represents a Selective Disclosure JWT, where the
 */
public class SdJwt(public val issuerJwt: SignedJWT, public val disclosures: Iterable<Disclosure>, public val keyBindingJwt: SignedJWT? = null) {
  init {
    require(issuerJwt.state == State.SIGNED) {
      "given issuerJwt \"${issuerJwt.serialize()}\" MUST be signed"
    }
    if (keyBindingJwt != null) {
      require(keyBindingJwt.state == State.SIGNED) {
        "given keyBindingJwt \"${keyBindingJwt.serialize()}\" MUST be signed"
      }
    }
  }

  /**
   * Serializes this sd-jwt to the serialization format described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-structure
   */
  public fun serialize(): String {
    return buildList {
      add(issuerJwt.serialize())
      addAll(disclosures.map { it.serialize() })
      add(keyBindingJwt?.serialize() ?: "")
    }.joinToString(separator)
  }

  public companion object {
    @JvmStatic
    public fun parse(input: String): SdJwt {
      val parts = input.split(separator)
      require(parts.isNotEmpty()) {
        "input must not be empty"
      }
      val keyBindingInput = parts[parts.size - 1]
      val keyBindingJwt = keyBindingInput.takeUnless { it.isEmpty() }?.run(SignedJWT::parse)
      return SdJwt(
        SignedJWT.parse(parts[0]),
        parts.subList(1, parts.size - 1).map { Disclosure.parse(it) },
        keyBindingJwt,
      )
    }
  }
}

public fun selectDisclosures(sdJwt: SdJwt, claimNames: Set<String>): Iterable<Disclosure> {
  SignedJWT.parse("").serialize()
  return emptyList()
}

public typealias HashFunc = (ByteArray) -> ByteArray

internal val mapper = jacksonObjectMapper().apply {
  enable(SerializationFeature.INDENT_OUTPUT)
  setSerializationInclusion(JsonInclude.Include.NON_NULL)
  setDefaultPrettyPrinter(CustomPrettyPrinter())
}

private class CustomPrettyPrinter : DefaultPrettyPrinter(
  DefaultPrettyPrinter().withSpacesInObjectEntries().withObjectIndenter(
    NopIndenter.instance
  )
) {
  init {
    this._objectFieldValueSeparatorWithSpaces = this._objectFieldValueSeparatorWithSpaces.substring(1)
  }

  override fun createInstance(): CustomPrettyPrinter {
    check(javaClass == CustomPrettyPrinter::class.java) { // since 2.10
      ("Failed `createInstance()`: " + javaClass.name
        + " does not override method; it has to")
    }
    return CustomPrettyPrinter()
  }

  @Throws(IOException::class)
  override fun writeArrayValueSeparator(g: JsonGenerator) {
    g.writeRaw(_separators.arrayValueSeparator)
    g.writeRaw(' ')
    _arrayIndenter.writeIndentation(g, _nesting)
  }

  @Throws(IOException::class)
  override fun writeObjectEntrySeparator(g: JsonGenerator) {
    g.writeRaw(_separators.objectEntrySeparator)
    g.writeRaw(' ')
    _objectIndenter.writeIndentation(g, _nesting)
  }
}

public class ObjectDisclosure(
  public val salt: String,
  public val claimName: String,
  public val claimValue: Any) : Disclosure {

  override fun serialize(): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", "$claimName", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}

private fun sha256(input: ByteArray): ByteArray = hashString("SHA-256", input)
private fun hashString(type: String, input: ByteArray): ByteArray {
  return MessageDigest
    .getInstance(type)
    .digest(input)
}

public interface Disclosure {
  public fun serialize(): String
  public fun digest(hashAlg: HashFunc): String {
    val e = serialize()
    return Base64URL.encode(hashAlg(e.toByteArray())).toString()
  }

  public companion object {
    @JvmStatic
    public fun parse(encodedDisclosure: String): Disclosure {
      // Decode the base64-encoded disclosure
      val disclosureJson = Base64URL(encodedDisclosure).decodeToString()

      // Parse the disclosure JSON into a list of elements
      val disclosureElems = mapper.readValue(disclosureJson, List::class.java)

      // Ensure that the disclosure is object or array disclosure
      when (disclosureElems.size) {
        3 -> {
          // Extract the elements
          val disclosureClaimName = disclosureElems[1] as? String
            ?: throw IllegalArgumentException("Second element of disclosure must be a string")

          // Create a Disclosure instance
          return ObjectDisclosure(
            salt = disclosureElems[0] as String,
            claimName = disclosureClaimName,
            claimValue = disclosureElems[2] as Any
          )
        }

        2 -> {
          // Create a Disclosure instance
          return ArrayDisclosure(
            salt = disclosureElems[0] as String,
            claimValue = disclosureElems[1] as Any
          )
        }

        else -> throw IllegalArgumentException("Disclosure \"$encodedDisclosure\" must have exactly 3 elements")
      }
    }
  }
}

public class ArrayDisclosure(
  public val salt: String,
  public val claimValue: Any) : Disclosure {

  override fun serialize(): String {
    val value = mapper.writeValueAsString(claimValue)
    val jsonEncoded = """["$salt", $value]"""

    return Base64URL.encode(jsonEncoded).toString()
  }
}

public open class BlindOption


// FlatBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-1-flat-sd-jwt
public class FlatBlindOption : BlindOption()

// SubClaimBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-2-structured-sd-jwt
public class SubClaimBlindOption(
  public val claimsToBlind: Map<String, BlindOption>
) : BlindOption()

public class AlwaysVisibleBlindOption : BlindOption()

// RecursiveBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-3-sd-jwt-with-recurs
public class RecursiveBlindOption : BlindOption()

public class ArrayBlindOption : BlindOption()


public interface ISaltGenerator {
  public fun generate(claim: String): String
}

public class SaltGenerator(private val numBytes: Int = 128 / 8) : ISaltGenerator {
  override fun generate(claim: String): String {
    val data = ByteArray(numBytes)
    SecureRandom().nextBytes(data)
    return Base64URL.encode(data).toString()
  }
}

public class DisclosureFactory(private val saltGen: ISaltGenerator) {
  public fun fromClaimAndValue(claim: String, claimValue: Any): Disclosure {
    val saltValue = saltGen.generate(claim)
    return ObjectDisclosure(saltValue, claim, claimValue)
  }

  public fun fromArrayValue(index: Int, claim: String, value: Any): Disclosure {
    val saltValue = saltGen.generate("$claim[$index]")
    return ArrayDisclosure(saltValue, value)
  }
}

private class ClaimSetBlinder(
  private val sdAlg: HashFunc,
  private val disclosureFactory: DisclosureFactory,
  private val totalDigests: (Int) -> Int,
  private val shuffle: (List<Any>) -> Unit
) {
  fun blindElementsRecursively(elems: List<Any>): Pair<List<Any>, List<Disclosure>> {
    val blinded = mutableListOf<Any>()
    val allDisclosures = mutableListOf<Disclosure>()
    for ((i, elem) in elems.withIndex()) {
      val claimsToBlind = mutableMapOf<String, BlindOption>()

      when (elem) {
        is Map<*, *> -> {
          elem.keys.forEach { k ->
            claimsToBlind[k as String] = RecursiveBlindOption()
          }

          val (blindedValue, ds) = toBlindedClaimsAndDisclosures(elem as Map<String, Any>, claimsToBlind)
          blinded.add(blindedValue)
          allDisclosures.addAll(ds)
        }

        is List<*> -> {
          val (blindedValue, ds) = blindElementsRecursively(elem as List<Any>)
          blinded.add(blindedValue)
          allDisclosures.addAll(ds)
        }

        else -> blinded.add(elem)
      }
    }
    return Pair(blinded, allDisclosures)
  }

  fun toBlindedClaimsAndDisclosures(
    claims: Map<String, Any>,
    claimsToBlind: Map<String, BlindOption>
  ): Pair<Map<String, Any>, List<Disclosure>> {
    val blindedClaims = mutableMapOf<String, Any>()
    val allDisclosures = mutableListOf<Disclosure>()
    val hashedDisclosures = mutableListOf<String>()

    for ((claimName, claimValue) in claims) {
      val blindOption = claimsToBlind[claimName]
      if (blindOption == null) {
        blindedClaims[claimName] = claimValue
        continue
      }

      when (blindOption) {
        is FlatBlindOption -> {
          val disclosure = disclosureFactory.fromClaimAndValue(claimName, claimValue)
          allDisclosures.add(disclosure)
          hashedDisclosures.add(disclosure.digest(sdAlg))
        }

        is SubClaimBlindOption -> {
          when (claimValue) {
            is Map<*, *> -> {
              val (blindedSubClaim, subClaimDisclosures) = toBlindedClaimsAndDisclosures(
                claimValue as Map<String, Any>,
                blindOption.claimsToBlind
              )
              blindedClaims[claimName] = blindedSubClaim
              allDisclosures.addAll(subClaimDisclosures)
            }

            else -> throw IllegalArgumentException("blind option not applicable to non-object types")
          }
        }

        is RecursiveBlindOption -> {
          val disclosure: Disclosure
          when (claimValue) {
            is List<*> -> {
              val (blindedSubClaims, subClaimDisclosures) = blindElementsRecursively(claimValue as List<Any>)
              allDisclosures.addAll(subClaimDisclosures)

              disclosure = disclosureFactory.fromClaimAndValue(claimName, blindedSubClaims)
            }

            is Map<*, *> -> {
              val subClaimsToBlind = (claimValue as Map<String, Any>).keys.associateWith { RecursiveBlindOption() }
              val (blindedSubClaims, subClaimDisclosures) = toBlindedClaimsAndDisclosures(
                claimValue,
                subClaimsToBlind
              )
              allDisclosures.addAll(subClaimDisclosures)

              disclosure = disclosureFactory.fromClaimAndValue(claimName, blindedSubClaims)
            }

            else -> {
              disclosure = disclosureFactory.fromClaimAndValue(claimName, claimValue)
            }
          }
          allDisclosures.add(disclosure)
          hashedDisclosures.add(disclosure.digest(sdAlg))
        }

        is ArrayBlindOption -> {
          when (claimValue) {
            is List<*> -> {
              val disclosures = claimValue.indices.map {
                disclosureFactory.fromArrayValue(it, claimName, claimValue[it]!!)
              }
              allDisclosures.addAll(disclosures)
              val arrayDisclosures = disclosures.map {
                mapOf(
                  "..." to it.digest(sdAlg)
                )
              }.toMutableList()

              repeat(totalDigests(arrayDisclosures.size) - arrayDisclosures.size) {
                val randBytes = ByteArray(32)
                SecureRandom().nextBytes(randBytes)

                arrayDisclosures.add(mapOf("..." to Base64URL.encode(sdAlg(randBytes)).toString()))
              }

              blindedClaims[claimName] = arrayDisclosures
            }

            else -> throw IllegalArgumentException("$claimValue must be an array")
          }
        }
      }
    }

    // Add some decoy hashed disclosures
    val totalToHash = totalDigests(hashedDisclosures.size)
    repeat(totalToHash - hashedDisclosures.size) {
      val randBytes = ByteArray(32)
      SecureRandom().nextBytes(randBytes)
      hashedDisclosures.add(Base64URL.encode(sdAlg(randBytes)).toString())
    }

    // Shuffle to prevent disclosure of ordering
    shuffle(hashedDisclosures)

    if (hashedDisclosures.isNotEmpty()) {
      blindedClaims[sdClaimName] = hashedDisclosures
    }
    return Pair(blindedClaims, allDisclosures)
  }

  companion object {
    const val sdClaimName = "_sd"
  }
}


public const val sdAlgClaimName: String = "_sd_alg"
public const val sha256Alg: String = "sha-256"

public class SdJwtSigner(
  public val signer: JWSSigner,
  public val saltGenerator: ISaltGenerator,
  private val disclosureFactory: DisclosureFactory = DisclosureFactory(saltGenerator),
  private val shuffle: (List<Any>) -> Unit = Collections::shuffle,
  private val totalDigests: (Int) -> Int = ::getNextPowerOfTwo
) {

  public fun blindAndSign(claimsData: String, claimsToBlind: Map<String, BlindOption>, alg: JWSAlgorithm, kid: String): SdJwt {
    val typeRef = object : TypeReference<LinkedHashMap<String, Any>>() {}
    val claimsMap = mapper.readValue(claimsData, typeRef)

    val csb = ClaimSetBlinder(
      sdAlg = ::sha256,
      disclosureFactory = disclosureFactory,
      totalDigests = totalDigests,
      shuffle = shuffle
    )

    val (blindedClaims, disclosures) = csb.toBlindedClaimsAndDisclosures(claimsMap, claimsToBlind)

    val blindedClaimsMap = blindedClaims.toMutableMap()
    blindedClaimsMap[sdAlgClaimName] = sha256Alg

    val payload = JWTClaimsSet.parse(blindedClaimsMap)

    val header = JWSHeader.Builder(alg)
      .type(JOSEObjectType.JWT)
      .keyID(kid)
      .build()

    val jwt = SignedJWT(header, payload)
    jwt.sign(signer)

    return SdJwt(jwt, disclosures)
  }

}

private fun getNextPowerOfTwo(n: Int): Int {
  if (n <= 0) {
    return 1
  }

  return 2.0.pow(ceil(log2((n + 1).toDouble())).toInt()).toInt()
}

