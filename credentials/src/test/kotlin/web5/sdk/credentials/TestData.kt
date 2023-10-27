package web5.sdk.credentials

const val TBDEX_PD = """
{
  "id": "ec11a434-fe24-479b-aae0-511428b37e4f",
  "format": {
    "jwt_vc": {
      "alg": [
        "ES256K",
        "EdDSA"
      ]
    }
  },
  "input_descriptors": [
    {
      "id": "7b928839-f0b1-4237-893d-b27124b57952",
      "constraints": {
        "fields": [
          {
            "path": [
              "${'$'}.iss",
              "${'$'}.vc.issuer"
            ],
            "filter": {
              "type": "string",
              "pattern": "^did:[^:]+:.+"
            }
          },
          {
            "path": [
              "${'$'}.vc.type[*]",
              "${'$'}.type[*]"
            ],
            "filter": {
              "type": "array",
              "contains": {
                "type": "string",
                "pattern": "^SanctionsCredential${'$'}"
              }
            }
          }
        ]
      }
    }
  ]
}
"""

@Suppress("MaximumLineLength")
const val VC_JWT =
  "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5Ono2TWtrdU5tSmF0ZUNUZXI1V0JycUhCVUM0YUM3TjlOV1NyTURKNmVkQXY1V0NmMiIsInN1YiI6ImRpZDprZXk6ejZNa2t1Tm1KYXRlQ1RlcjVXQnJxSEJVQzRhQzdOOU5XU3JNREo2ZWRBdjVXQ2YyIiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiaWQiOiIxNjk4NDIyNDAxMzUyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNhbmN0aW9uc0NyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJpc3N1YW5jZURhdGUiOiIyMDIzLTEwLTI3VDE2OjAwOjAxWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1ra3VObUphdGVDVGVyNVdCcnFIQlVDNGFDN045TldTck1ESjZlZEF2NVdDZjIiLCJiZWVwIjoiYm9vcCJ9fX0.Xhd9nDdkGarYFr6FP7wqsgj5CK3oGTfKU2LHNMvFIsvatgYlSucShDPI8uoeJ_G31uYPke-LJlRy-WVIhkudDg"
