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

import org.openapitools.server.models.CredentialIssuanceRequestCredential
import org.openapitools.server.models.CredentialIssuanceRequestOptions

/**
 * 
 * @param credential 
 * @param options 
 */
data class CredentialIssuanceRequest(
    val credential: CredentialIssuanceRequestCredential,
    val options: CredentialIssuanceRequestOptions
) 

