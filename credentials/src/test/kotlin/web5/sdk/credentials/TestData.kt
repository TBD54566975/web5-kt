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