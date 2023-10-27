package web5.security

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Collections
import kotlin.math.ceil
import kotlin.math.log2
import kotlin.math.pow

/**
 * Hash implementations supported by this library.
 */
public enum class Hash(
  public val hashFunc: HashFunc,
  public val ianaName: String,
) {
  /** The sha-256 hash algorithm as registered in https://www.iana.org/assignments/named-information/named-information.xhtml */
  SHA_256({ hashString("SHA-256", it) }, "sha-256"),

  /** The sha-512 hash algorithm as registered in https://www.iana.org/assignments/named-information/named-information.xhtml */
  SHA_512({ hashString("SHA-512", it) }, "sha-512")
}

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
          hashedDisclosures.add(disclosure.digest(sdAlg))
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
                  blindedArrayKey to it.digest(sdAlg)
                )
              }.toMutableList()

              repeat(totalDigests(arrayDisclosures.size) - arrayDisclosures.size) {
                val randBytes = ByteArray(32)
                SecureRandom().nextBytes(randBytes)

                arrayDisclosures.add(mapOf(blindedArrayKey to Base64URL.encode(sdAlg(randBytes)).toString()))
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
}

public const val sdClaimName: String = "_sd"

/** The _sd_alg claim name. */
public const val sdAlgClaimName: String = "_sd_alg"

/**
 * A signer that is capable of producing [SdJwt] given some parameters. */
public class SdJwtBlinder(
  saltGenerator: ISaltGenerator = SaltGenerator(),
  private val hash: Hash = Hash.SHA_256,
  private val shuffle: (List<Any>) -> Unit = Collections::shuffle,
  private val totalDigests: (Int) -> Int = ::getNextPowerOfTwo,
  mapper: ObjectMapper = defaultMapper,
) {
  private val disclosureFactory: DisclosureFactory = DisclosureFactory(saltGenerator, mapper)

  /**
   * Returns an [SdJwt.Builder] with the [SdJwt.Builder.jwtClaimsSet] blinded and [SdJwt.Builder.disclosures] fields
   * set. The [SdJwt.Builder.jwtClaimsSet] field is also known as the SD-JWT Payload in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-sd-jwt-payload
   *
   * Note: You must set the [SdJwt.Builder.issuerHeader] before calling [SdJwt.Builder.build].
   */
  public fun blind(
    claimsData: String,
    claimsToBlind: Map<String, BlindOption>): SdJwt.Builder {
    val typeRef = object : TypeReference<LinkedHashMap<String, Any>>() {}
    val claimsMap = defaultMapper.readValue(claimsData, typeRef)

    val csb = ClaimSetBlinder(
      sdAlg = hash.hashFunc,
      disclosureFactory = disclosureFactory,
      totalDigests = totalDigests,
      shuffle = shuffle,
    )

    val (blindedClaims, disclosures) = csb.toBlindedClaimsAndDisclosures(claimsMap, claimsToBlind)

    val blindedClaimsMap = blindedClaims.toMutableMap()
    blindedClaimsMap[sdAlgClaimName] = hash.ianaName

    val payload = JWTClaimsSet.parse(blindedClaimsMap)

    return SdJwt.Builder(jwtClaimsSet = payload, disclosures = disclosures)
  }

}

private fun getNextPowerOfTwo(n: Int): Int {
  if (n <= 0) {
    return 1
  }

  return 2.0.pow(ceil(log2((n + 1).toDouble())).toInt()).toInt()
}

private class DisclosureFactory(
  private val saltGen: ISaltGenerator,
  private val mapper: ObjectMapper) {
  fun fromClaimAndValue(claim: String, claimValue: Any): Disclosure {
    val saltValue = saltGen.generate(claim)
    return ObjectDisclosure(saltValue, claim, claimValue, mapper = mapper)
  }

  fun fromArrayValue(index: Int, claim: String, value: Any): Disclosure {
    val saltValue = saltGen.generate("$claim[$index]")
    return ArrayDisclosure(saltValue, value, mapper = mapper)
  }
}
