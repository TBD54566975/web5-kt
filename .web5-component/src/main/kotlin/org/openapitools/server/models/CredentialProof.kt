/**
* web5 SDK test server
* No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
*
* The version of the OpenAPI document: 1.0.0
* 
*
* NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
* https://openapi-generator.tech
* Do not edit the class manually.
*/
package org.openapitools.server.models


/**
 * 
 * @param type 
 * @param created 
 * @param challenge 
 * @param domain 
 * @param nonce 
 * @param verificationMethod 
 * @param proofPurpose 
 * @param jws 
 * @param proofValue 
 */
data class CredentialProof(
    val type: kotlin.String,
    val created: kotlin.String,
    val challenge: kotlin.String,
    val domain: kotlin.String,
    val nonce: kotlin.String,
    val verificationMethod: kotlin.String,
    val proofPurpose: kotlin.String,
    val jws: kotlin.String,
    val proofValue: kotlin.String
) 

