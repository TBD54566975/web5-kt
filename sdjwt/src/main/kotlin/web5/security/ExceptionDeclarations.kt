package web5.security

/**
 * Exception thrown when a "_sd" key does not refer to an array as required.
 */
public class SdKeyNotArrayException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when a value in "_sd" is not a string as required.
 */
public class SdValueNotStringException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the value of "..." is not a string as required.
 */
public class EllipsisValueNotStringException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the parent of an array element digest is not an array as required.
 */
public class ParentNotArrayException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when a digest is found more than once, which is not allowed.
 */
public class DuplicateDigestException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the insertion point for an object disclosure is not a map as required.
 */
public class InvalidObjectDisclosureInsertionPointException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the insertion point for an array disclosure is not an array as required.
 */
public class InvalidArrayDisclosureInsertionPointException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when a claim name already exists in the claims set.
 */
public class ClaimNameAlreadyExistsException(message: String) : Exception(message)

/**
 * Exception thrown when the "_sd_alg" claim value is not a string as required.
 */
public class SdAlgValueNotStringException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the "_sd_alg" claim value represents a hash algorithm name that's not supported.
 */
public class HashNameNotSupportedException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the blind option is not valid.
 */
public class BlindOptionNotValidException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the claim value is not an array as required.
 */
public class ClaimValueIsNotArrayException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the "kty" value of a JWK is neither of `EC` nor `OKP` as required.
 */
public class InvalidJwkException(message: String) : RuntimeException(message)

/**
 * Exception thrown when the second element of a 3-element disclosure JSON array is not a string.
 */
public class DisclosureClaimNameNotStringException(message: String) : IllegalArgumentException(message)

/**
 * Exception thrown when the size of a disclosure JSON array is neither 2 nor 3.
 */
public class DisclosureSizeNotValidException(message: String) : IllegalArgumentException(message)
