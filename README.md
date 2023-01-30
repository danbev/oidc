## OpenID Connect exploration project
This project contains exploration code and note about OIDC.

### Decoding a JWT
First we need to inspect the header:
```console
$ cargo r --quiet --bin id_token
Header { typ: Some("JWT"), alg: RS256, cty: None, jku: None, jwk: None, kid: Some("78167F727DEC5D801DD1C8784C704A1C880EC0E1"), x5u: None, x5c: None, x5t: Some("eBZ_cn3sXYAd0ch4THBKHIgOwOE"), x5t_s256: None }
typ: Some("JWT")
alg: RS256
kid: "78167F727DEC5D801DD1C8784C704A1C880EC0E1"
x5t: "eBZ_cn3sXYAd0ch4THBKHIgOwOE"
```
Notice that key id field (`kid`), and the `x5t` which is an X.509 thumbprint.

So how do we find the certificate for this matching this `kid`. 
We can issue a call to the openif-configuration using the following command:
```console
$ curl -s -L https://token.actions.githubusercontent.com/.well-known/openid-configuration | jq
{
  "issuer": "https://token.actions.githubusercontent.com",
  "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks",
  "subject_types_supported": [
    "public",
    "pairwise"
  ],
  "response_types_supported": [
    "id_token"
  ],
  "claims_supported": [
    "sub",
    "aud",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "ref",
    "repository",
    "repository_id",
    "repository_owner",
    "repository_owner_id",
    "run_id",
    "run_number",
    "run_attempt",
    "actor",
    "actor_id",
    "workflow",
    "workflow_ref",
    "workflow_sha",
    "head_ref",
    "base_ref",
    "event_name",
    "ref_type",
    "environment",
    "environment_node_id",
    "job_workflow_ref",
    "job_workflow_sha",
    "repository_visibility"
  ],
  "id_token_signing_alg_values_supported": [
    "RS256"
  ],
  "scopes_supported": [
    "openid"
  ]
}
```
And we can use the the value of `jwks_uri` to show the keys:
```console
$ curl -s -L https://token.actions.githubusercontent.com/.well-known/jwks | jq '.keys[] | select(.kid=="78167F727DEC5D801DD1C8784C704A1C880EC0E1")'
{
  "n": "4WpHpoBYsVBVfSlfgnRbdPMxP3Eb7rFqE48e4pPM4qH_9EsUZIi21LjOu8UkKn14L4hrRfzfRHG7VQSbxXBU1Qa-xM5yVxdmfQZKBxQnPWaE1v7edjxq1ZYnqHIp90Uvnw6798xMCSvI_V3FR8tix5GaoTgkixXlPc-ozifMyEZMmhvuhfDsSxQeTSHGPlWfGkX0id_gYzKPeI69EGtQ9ZN3PLTdoAI8jxlQ-jyDchi9h2ax6hgMLDsMZyiIXnF2UYq4j36Cs5RgdC296d0hEOHN0WYZE-xPl7y_A9UHcVjrxeGfVOuTBXqjowofimn4ESnVXNReCsOwZCJlvJzfpQ",
  "kty": "RSA",
  "kid": "78167F727DEC5D801DD1C8784C704A1C880EC0E1",
  "alg": "RS256",
  "e": "AQAB",
  "use": "sig",
  "x5c": [
    "MIIDrDCCApSgAwIBAgIQMPdKi0TFTMqmg1HHo6FfsDANBgkqhkiG9w0BAQsFADA2MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVkaW8uY29tMB4XDTIyMDEwNTE4NDcyMloXDTI0MDEwNTE4NTcyMlowNjE0MDIGA1UEAxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFqR6aAWLFQVX0pX4J0W3TzMT9xG+6xahOPHuKTzOKh//RLFGSIttS4zrvFJCp9eC+Ia0X830Rxu1UEm8VwVNUGvsTOclcXZn0GSgcUJz1mhNb+3nY8atWWJ6hyKfdFL58Ou/fMTAkryP1dxUfLYseRmqE4JIsV5T3PqM4nzMhGTJob7oXw7EsUHk0hxj5VnxpF9Inf4GMyj3iOvRBrUPWTdzy03aACPI8ZUPo8g3IYvYdmseoYDCw7DGcoiF5xdlGKuI9+grOUYHQtvendIRDhzdFmGRPsT5e8vwPVB3FY68Xhn1TrkwV6o6MKH4pp+BEp1VzUXgrDsGQiZbyc36UCAwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBRZBaZCR9ghvStfcWaGwuHGjrfTgzAdBgNVHQ4EFgQUWQWmQkfYIb0rX3FmhsLhxo6304MwDQYJKoZIhvcNAQELBQADggEBAGNdfALe6mdxQ67QL8GlW4dfFwvCX87JOeZThZ9uCj1+x1xUnywoR4o5q2DVI/JCvBRPn0BUb3dEVWLECXDHGjblesWZGMdSGYhMzWRQjVNmCYBC1ZM5QvonWCBcGkd72mZx0eFHnJCAP/TqEEpRvMHR+OOtSiZWV9zZpF1tf06AjKwT64F9V8PCmSIqPJXcTQXKKfkHZmGUk9AYF875+/FfzF89tCnT53UEh5BldFz0SAls+NhexbW/oOokBNCVqe+T2xXizktbFnFAFaomvwjVSvIeu3i/0Ygywl+3s5izMEsZ1T1ydIytv4FZf2JCHgRpmGPWJ5A7TpxuHSiE8Do="
  ],
  "x5t": "eBZ_cn3sXYAd0ch4THBKHIgOwOE"
}
```
And we can inspect the certificate using:
```console
$ curl -s -L https://token.actions.githubusercontent.com/.well-known/jwks | jq '.keys[] | select(.kid=="78167F727DEC5D801DD1C8784C704A1C880EC0E1")' | jq -r '.x5c[0]' | base64 -d | openssl x509 -inform der -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            30:f7:4a:8b:44:c5:4c:ca:a6:83:51:c7:a3:a1:5f:b0
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN = vsts-vstsghrt-gh-vso-oauth.visualstudio.com
        Validity
            Not Before: Jan  5 18:47:22 2022 GMT
            Not After : Jan  5 18:57:22 2024 GMT
        Subject: CN = vsts-vstsghrt-gh-vso-oauth.visualstudio.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:e1:6a:47:a6:80:58:b1:50:55:7d:29:5f:82:74:
                    5b:74:f3:31:3f:71:1b:ee:b1:6a:13:8f:1e:e2:93:
                    cc:e2:a1:ff:f4:4b:14:64:88:b6:d4:b8:ce:bb:c5:
                    24:2a:7d:78:2f:88:6b:45:fc:df:44:71:bb:55:04:
                    9b:c5:70:54:d5:06:be:c4:ce:72:57:17:66:7d:06:
                    4a:07:14:27:3d:66:84:d6:fe:de:76:3c:6a:d5:96:
                    27:a8:72:29:f7:45:2f:9f:0e:bb:f7:cc:4c:09:2b:
                    c8:fd:5d:c5:47:cb:62:c7:91:9a:a1:38:24:8b:15:
                    e5:3d:cf:a8:ce:27:cc:c8:46:4c:9a:1b:ee:85:f0:
                    ec:4b:14:1e:4d:21:c6:3e:55:9f:1a:45:f4:89:df:
                    e0:63:32:8f:78:8e:bd:10:6b:50:f5:93:77:3c:b4:
                    dd:a0:02:3c:8f:19:50:fa:3c:83:72:18:bd:87:66:
                    b1:ea:18:0c:2c:3b:0c:67:28:88:5e:71:76:51:8a:
                    b8:8f:7e:82:b3:94:60:74:2d:bd:e9:dd:21:10:e1:
                    cd:d1:66:19:13:ec:4f:97:bc:bf:03:d5:07:71:58:
                    eb:c5:e1:9f:54:eb:93:05:7a:a3:a3:0a:1f:8a:69:
                    f8:11:29:d5:5c:d4:5e:0a:c3:b0:64:22:65:bc:9c:
                    df:a5
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                DNS:vsts-vstsghrt-gh-vso-oauth.visualstudio.com
            X509v3 Authority Key Identifier: 
                keyid:59:05:A6:42:47:D8:21:BD:2B:5F:71:66:86:C2:E1:C6:8E:B7:D3:83

            X509v3 Subject Key Identifier: 
                59:05:A6:42:47:D8:21:BD:2B:5F:71:66:86:C2:E1:C6:8E:B7:D3:83
    Signature Algorithm: sha256WithRSAEncryption
         63:5d:7c:02:de:ea:67:71:43:ae:d0:2f:c1:a5:5b:87:5f:17:
         0b:c2:5f:ce:c9:39:e6:53:85:9f:6e:0a:3d:7e:c7:5c:54:9f:
         2c:28:47:8a:39:ab:60:d5:23:f2:42:bc:14:4f:9f:40:54:6f:
         77:44:55:62:c4:09:70:c7:1a:36:e5:7a:c5:99:18:c7:52:19:
         88:4c:cd:64:50:8d:53:66:09:80:42:d5:93:39:42:fa:27:58:
         20:5c:1a:47:7b:da:66:71:d1:e1:47:9c:90:80:3f:f4:ea:10:
         4a:51:bc:c1:d1:f8:e3:ad:4a:26:56:57:dc:d9:a4:5d:6d:7f:
         4e:80:8c:ac:13:eb:81:7d:57:c3:c2:99:22:2a:3c:95:dc:4d:
         05:ca:29:f9:07:66:61:94:93:d0:18:17:ce:f9:fb:f1:5f:cc:
         5f:3d:b4:29:d3:e7:75:04:87:90:65:74:5c:f4:48:09:6c:f8:
         d8:5e:c5:b5:bf:a0:ea:24:04:d0:95:a9:ef:93:db:15:e2:ce:
         4b:5b:16:71:40:15:aa:26:bf:08:d5:4a:f2:1e:bb:78:bf:d1:
         88:32:c2:5f:b7:b3:98:b3:30:4b:19:d5:3d:72:74:8c:ad:bf:
         81:59:7f:62:42:1e:04:69:98:63:d6:27:90:3b:4e:9c:6e:1d:
         28:84:f0:3a
-----BEGIN CERTIFICATE-----
MIIDrDCCApSgAwIBAgIQMPdKi0TFTMqmg1HHo6FfsDANBgkqhkiG9w0BAQsFADA2
MTQwMgYDVQQDEyt2c3RzLXZzdHNnaHJ0LWdoLXZzby1vYXV0aC52aXN1YWxzdHVk
aW8uY29tMB4XDTIyMDEwNTE4NDcyMloXDTI0MDEwNTE4NTcyMlowNjE0MDIGA1UE
AxMrdnN0cy12c3RzZ2hydC1naC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFqR6aAWLFQVX0pX4J0W3Tz
MT9xG+6xahOPHuKTzOKh//RLFGSIttS4zrvFJCp9eC+Ia0X830Rxu1UEm8VwVNUG
vsTOclcXZn0GSgcUJz1mhNb+3nY8atWWJ6hyKfdFL58Ou/fMTAkryP1dxUfLYseR
mqE4JIsV5T3PqM4nzMhGTJob7oXw7EsUHk0hxj5VnxpF9Inf4GMyj3iOvRBrUPWT
dzy03aACPI8ZUPo8g3IYvYdmseoYDCw7DGcoiF5xdlGKuI9+grOUYHQtvendIRDh
zdFmGRPsT5e8vwPVB3FY68Xhn1TrkwV6o6MKH4pp+BEp1VzUXgrDsGQiZbyc36UC
AwEAAaOBtTCBsjAOBgNVHQ8BAf8EBAMCBaAwCQYDVR0TBAIwADAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwNgYDVR0RBC8wLYIrdnN0cy12c3RzZ2hydC1n
aC12c28tb2F1dGgudmlzdWFsc3R1ZGlvLmNvbTAfBgNVHSMEGDAWgBRZBaZCR9gh
vStfcWaGwuHGjrfTgzAdBgNVHQ4EFgQUWQWmQkfYIb0rX3FmhsLhxo6304MwDQYJ
KoZIhvcNAQELBQADggEBAGNdfALe6mdxQ67QL8GlW4dfFwvCX87JOeZThZ9uCj1+
x1xUnywoR4o5q2DVI/JCvBRPn0BUb3dEVWLECXDHGjblesWZGMdSGYhMzWRQjVNm
CYBC1ZM5QvonWCBcGkd72mZx0eFHnJCAP/TqEEpRvMHR+OOtSiZWV9zZpF1tf06A
jKwT64F9V8PCmSIqPJXcTQXKKfkHZmGUk9AYF875+/FfzF89tCnT53UEh5BldFz0
SAls+NhexbW/oOokBNCVqe+T2xXizktbFnFAFaomvwjVSvIeu3i/0Ygywl+3s5iz
MEsZ1T1ydIytv4FZf2JCHgRpmGPWJ5A7TpxuHSiE8Do=
-----END CERTIFICATE-----
```
