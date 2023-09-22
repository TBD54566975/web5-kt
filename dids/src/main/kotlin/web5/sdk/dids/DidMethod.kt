package web5.sdk.dids

public interface DidMethod {
  public fun create(): Did
  
  public fun resolve(didUrl: String): DidResolutionResult
}