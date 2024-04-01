package web5.sdk.testing

/**
 * Represents a set of test vectors as specified in https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/vectors.schema.json
 *
 * See https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/README.md for more details.
 */
public class TestVectors<I,O>(
  public val description: String,
  public val vectors: List<TestVector<I,O>>
)

/**
 * Represents a single test vector as specified in https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/vectors.schema.json#L11
 *
 * See https://github.com/TBD54566975/sdk-development/blob/main/web5-test-vectors/README.md for more details.
 */
public class TestVector<I,O>(
  public val description: String,
  public val input: I,
  public val output: O?,
  public val errors: Boolean? = false
)