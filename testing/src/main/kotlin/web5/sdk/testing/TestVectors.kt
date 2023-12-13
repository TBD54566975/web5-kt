package web5.sdk.testing

/**
 * Represents a set of test vectors as specified in https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/vectors.schema.json
 *
 * See https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/README.md for more details.
 */
public class TestVectors<T>(
  public val description: String,
  public val vectors: List<TestVector<T>>
)

/**
 * Represents a single test vector as specified in https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/vectors.schema.json#L11
 *
 * See https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/README.md for more details.
 */
public class TestVector<T>(
  public val description: String,
  public val input: T,
  public val output: String?,
  public val errors: Boolean?,
)