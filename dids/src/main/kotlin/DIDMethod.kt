package web5.dids

import foundation.identity.did.DID
import foundation.identity.did.DIDDocument

// DIDMethod encapsulates all the operations that a DID method can do according to https://www.w3.org/TR/did-core/#method-operations
public interface DIDMethod {
  //  A DID method specification MUST define how authorization is performed to execute all operations, including any necessary cryptographic processes.
  public fun authorize(operation: DIDMethodOperation, authorization: AuthorizationInfo? = null): Boolean

  /**
   * Assembles a creator object. This object can be used in the DIDMethod.authorize as a parameter.
   */
  public fun creator(opts: CreateDIDOptions): DIDCreator
}

public interface AuthorizationInfo

public interface CreateDIDOptions

public interface DIDMethodOperation

public class DIDCreationResult(
  public val did: DID,
  public val document: DIDDocument,
)

public interface DIDCreator : DIDMethodOperation {
  public fun create(): DIDCreationResult
}

public interface DIDCreationMetadata
