package web5.security

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

/** The sha-256 hash algorithm as registered in https://www.iana.org/assignments/named-information/named-information.xhtml */
public fun sha256(input: ByteArray): ByteArray = hashString("SHA-256", input)

/** The hash name string of `shah-256` from the IANA registry https://www.iana.org/assignments/named-information/named-information.xhtml */
public const val sha256Alg: String = "sha-256"

/** The sha-512 hash algorithm as registered in https://www.iana.org/assignments/named-information/named-information.xhtml */
public fun sha512(input: ByteArray): ByteArray = hashString("SHA-512", input)
private fun hashString(type: String, input: ByteArray): ByteArray {
  return MessageDigest.getInstance(type)
    .digest(input)
}

/** Base class to be used for any blinding strategies. */
public sealed class BlindOption

/** FlatBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-1-flat-sd-jwt */
public object FlatBlindOption : BlindOption()

/** SubClaimBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-2-structured-sd-jwt */
public class SubClaimBlindOption(
  public val claimsToBlind: Map<String, BlindOption>
) : BlindOption()

/** RecursiveBlindOption implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-04.html#name-option-3-sd-jwt-with-recurs */
public object RecursiveBlindOption : BlindOption()

/** Implements https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-array-elements */
public object ArrayBlindOption : BlindOption()


/** Interface for generating salt values as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#disclosures_for_object_properties */
public interface ISaltGenerator {
  /** Returns a base64url encoded string over cryptographically secure pseudo random data. */
  public fun generate(claim: String): String
}

/** Simple implementation of [ISaltGenerator]. */
public class SaltGenerator(private val numBytes: Int = 128 / 8) : ISaltGenerator {
  override fun generate(claim: String): String {
    val data = ByteArray(numBytes)
    SecureRandom().nextBytes(data)
    return Base64URL.encode(data).toString()
  }
}

private class ClaimSetBlinder(
  private val sdAlg: HashFunc,
  private val disclosureFactory: DisclosureFactory,
  private val totalDigests: (Int) -> Int,
  private val shuffle: (List<Any>) -> Unit,
  private val mapper: ObjectMapper,
) {
  fun blindElementsRecursively(elems: List<Any>): Pair<List<Any>, List<Disclosure>> {
    val blinded = mutableListOf<Any>()
    val allDisclosures = mutableListOf<Disclosure>()
    for (elem in elems) {
      val claimsToBlind = mutableMapOf<String, BlindOption>()

      when (elem) {
        is Map<*, *> -> {
          elem.keys.forEach { k ->
            claimsToBlind[k as String] = RecursiveBlindOption
          }

          @Suppress("UNCHECKED_CAST")
          val elemMap = elem as Map<String, Any>

          val (blindedValue, ds) = toBlindedClaimsAndDisclosures(elemMap, claimsToBlind)
          blinded.add(blindedValue)
          allDisclosures.addAll(ds)
        }

        is List<*> -> {
          @Suppress("UNCHECKED_CAST")
          val elemList = elem as List<Any>

          val (blindedValue, ds) = blindElementsRecursively(elemList)
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
          hashedDisclosures.add(disclosure.digest(sdAlg, mapper))
        }

        is SubClaimBlindOption -> {
          when (claimValue) {
            is Map<*, *> -> {
              @Suppress("UNCHECKED_CAST")
              val claimValueMap = claimValue as Map<String, Any>
              val (blindedSubClaim, subClaimDisclosures) = toBlindedClaimsAndDisclosures(
                claimValueMap,
                blindOption.claimsToBlind
              )
              blindedClaims[claimName] = blindedSubClaim
              allDisclosures.addAll(subClaimDisclosures)
            }

            else -> throw IllegalArgumentException("blind option not applicable to non-object types")
          }
        }

        is RecursiveBlindOption -> {
          val disclosure = processRecursiveDisclosure(claimValue, allDisclosures, claimName)
          allDisclosures.add(disclosure)
          hashedDisclosures.add(disclosure.digest(sdAlg, mapper))
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
                  "..." to it.digest(sdAlg, mapper)
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

  private fun processRecursiveDisclosure(
    claimValue: Any,
    allDisclosures: MutableList<Disclosure>,
    claimName: String): Disclosure {
    val disclosure: Disclosure

    when (claimValue) {
      is List<*> -> {
        @Suppress("UNCHECKED_CAST")
        val claimValueList = claimValue as List<Any>
        val (blindedSubClaims, subClaimDisclosures) = blindElementsRecursively(
          claimValueList
        )
        allDisclosures.addAll(subClaimDisclosures)

        disclosure = disclosureFactory.fromClaimAndValue(claimName, blindedSubClaims)
      }

      is Map<*, *> -> {
        @Suppress("UNCHECKED_CAST")
        val claimValueMap = claimValue as Map<String, Any>
        val subClaimsToBlind =
          claimValueMap
            .keys.associateWith { RecursiveBlindOption }
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
    return disclosure
  }

  companion object {
    const val sdClaimName = "_sd"
  }
}

/** The _sd_alg claim name. */
public const val sdAlgClaimName: String = "_sd_alg"

/** A signer that is capable of producing [SdJwt] given some parameters. */
public class SdJwtSigner(
  public val signer: JWSSigner,
  public val saltGenerator: ISaltGenerator,
  private val sdAlg: HashFunc = ::sha256,
  private val shuffle: (List<Any>) -> Unit = Collections::shuffle,
  private val totalDigests: (Int) -> Int = ::getNextPowerOfTwo,
  private val mapper: ObjectMapper = defaultMapper,
) {
  private val disclosureFactory: DisclosureFactory = DisclosureFactory(saltGenerator)

  /**
   * Returns an [SdJwt] with the [SdJwt.issuerJwt] component signed, and the claims blinded according [claimsToBlind]
   * parameter.
   */
  public fun blindAndSign(
    claimsData: String,
    claimsToBlind: Map<String, BlindOption>,
    alg: JWSAlgorithm,
    kid: String): SdJwt {
    val typeRef = object : TypeReference<LinkedHashMap<String, Any>>() {}
    val claimsMap = defaultMapper.readValue(claimsData, typeRef)

    val csb = ClaimSetBlinder(
      sdAlg = sdAlg,
      disclosureFactory = disclosureFactory,
      totalDigests = totalDigests,
      shuffle = shuffle,
      mapper = mapper,
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

private class DisclosureFactory(private val saltGen: ISaltGenerator) {
  fun fromClaimAndValue(claim: String, claimValue: Any): Disclosure {
    val saltValue = saltGen.generate(claim)
    return ObjectDisclosure(saltValue, claim, claimValue)
  }

  fun fromArrayValue(index: Int, claim: String, value: Any): Disclosure {
    val saltValue = saltGen.generate("$claim[$index]")
    return ArrayDisclosure(saltValue, value)
  }
}
