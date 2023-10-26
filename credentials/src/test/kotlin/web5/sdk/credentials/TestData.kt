package web5.sdk.credentials

const val PRESENTATION_DEFINITION = """
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
                            "const": "did:ion:EiD6Jcwrqb5lFLFWyW59uLizo5lBuChieiqtd0TFN0xsng:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJ6cC1mNnFMTW1EazZCNDFqTFhIXy1kd0xOLW9DS2lTcDJaa19WQ2t4X3ZFIiwicHVibGljS2V5SndrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6IjNmVFk3VXpBaU9VNVpGZ05VVjl3bm5pdEtGQk51RkNPLWxlRXBDVzhHOHMiLCJ5IjoidjJoNlRqTDF0TnYwSDNWb09Fbll0UVBxRHZOVC0wbVdZUUdLTGRSakJ3ayJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV0sInNlcnZpY2VzIjpbXX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpQjk3STI2bmUwdkhXYXduODk1Y1dnVlE0cFF5NmN1OUFlSzV2aW44X3JVeXcifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaURqSmlEdm9RekstRl94V05VVzlzMTBUVmlpdEI0Z1JoS09iYlh2S1pwdlNRIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCbEk1NWx6b3JoeE42TVBqUlZtV2ZZY3MxNzNKOFk3S0hTeU5LcmZiTzVfdyJ9fQ"
                        }
                    },
                    {
                        "path": [
                            "${'$'}.vc.type[*]",
                            "${'$'}.type[*]"
                        ],
                        "filter": {
                            "type": "string",
                            "pattern": "^SanctionCredential${'$'}"
                        }
                    }
                ]
            }
        }
    ]
}"""