use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, Validation};
use std::collections::HashMap;
use std::fs;

const TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImVCWl9jbjNzWFlBZDBjaDRUSEJLSElnT3dPRSIsImtpZCI6Ijc4MTY3RjcyN0RFQzVEODAxREQxQzg3ODRDNzA0QTFDODgwRUMwRTEifQ.eyJqdGkiOiI3OGI1ZTY1OC03MTY4LTRhN2MtYmIxMS1mYTg5OTlmOGEzNWYiLCJzdWIiOiJyZXBvOnRydXN0aWZpY2F0aW9uL3NvdXJjZS1kaXN0cmlidXRlZDpyZWY6cmVmcy9oZWFkcy9tYWluIiwiYXVkIjoiaHR0cHM6Ly9naXRodWIuY29tL3RydXN0aWZpY2F0aW9uIiwicmVmIjoicmVmcy9oZWFkcy9tYWluIiwic2hhIjoiZDgyNDgwMDUwNDA5ZTc2YjhiM2E3OWY3ZjdiMjczNzFjMjAzOTdlNCIsInJlcG9zaXRvcnkiOiJ0cnVzdGlmaWNhdGlvbi9zb3VyY2UtZGlzdHJpYnV0ZWQiLCJyZXBvc2l0b3J5X293bmVyIjoidHJ1c3RpZmljYXRpb24iLCJyZXBvc2l0b3J5X293bmVyX2lkIjoiMTE1MTExMDkzIiwicnVuX2lkIjoiNDA0NDk3MjkyMyIsInJ1bl9udW1iZXIiOiI4MyIsInJ1bl9hdHRlbXB0IjoiMSIsInJlcG9zaXRvcnlfdmlzaWJpbGl0eSI6InB1YmxpYyIsInJlcG9zaXRvcnlfaWQiOiI1NjYzODkzNDUiLCJhY3Rvcl9pZCI6IjQzMjM1MSIsImFjdG9yIjoiZGFuYmV2Iiwid29ya2Zsb3ciOiJTU0NTIFdvcmtmbG93IiwiaGVhZF9yZWYiOiIiLCJiYXNlX3JlZiI6IiIsImV2ZW50X25hbWUiOiJwdXNoIiwicmVmX3R5cGUiOiJicmFuY2giLCJ3b3JrZmxvd19yZWYiOiJ0cnVzdGlmaWNhdGlvbi9zb3VyY2UtZGlzdHJpYnV0ZWQvLmdpdGh1Yi93b3JrZmxvd3Mvc3Njcy55YW1sQHJlZnMvaGVhZHMvbWFpbiIsIndvcmtmbG93X3NoYSI6ImQ4MjQ4MDA1MDQwOWU3NmI4YjNhNzlmN2Y3YjI3MzcxYzIwMzk3ZTQiLCJqb2Jfd29ya2Zsb3dfcmVmIjoidHJ1c3RpZmljYXRpb24vc291cmNlLWRpc3RyaWJ1dGVkLy5naXRodWIvd29ya2Zsb3dzL3NzY3MueWFtbEByZWZzL2hlYWRzL21haW4iLCJqb2Jfd29ya2Zsb3dfc2hhIjoiZDgyNDgwMDUwNDA5ZTc2YjhiM2E3OWY3ZjdiMjczNzFjMjAzOTdlNCIsImlzcyI6Imh0dHBzOi8vdG9rZW4uYWN0aW9ucy5naXRodWJ1c2VyY29udGVudC5jb20iLCJuYmYiOjE2NzUwODkwNjUsImV4cCI6MTY3NTA4OTk2NSwiaWF0IjoxNjc1MDg5NjY1fQ.MJpvNZvO2m5mDCpHfnlTGOrkDJs-qSBRagknx0MVzHpygUZg7j4o8uC1_YVqWzROE8-2wbBFCuCLcDjjR0goQ3YKOOoGLPkJNfgMKBaE0zEFYZ_qxtsOF38Deea9dUEKdJCffeBDoCAWG_pkgM7uVhWuZSYQAeUVFU2FVKJnMdiZBCdQAkR_-D6RJlOu8MjeRV93gKUpaA-_6WrXYgoIrVXwfAb6smd8vkpBaKqcqdiXCXZnFfLe-nM9Mzfk6Eaw8-32StVmFbjAoIBRXNt1XSVdkXJP9z_TYxxKN1ultaTXiRHeEKUOgo1KC3Q4RofqRHh3f_JdB6fQ0kIk7Mohxg";

fn main() {
    let token = fs::read_to_string("token").unwrap();
    println!("{}", &token.trim());
    let header = decode_header(&token).unwrap();
    println!("{:?}", &header);
    println!("typ: {:?}", &header.typ);
    println!("alg: {:?}", &header.alg);
    println!("kid: {:?}", &header.kid.as_ref().unwrap());
    println!("x5t: {:?}", &header.x5t.unwrap());

    let jwt_base64 = fs::read_to_string("jwks").unwrap();
    let jwks: jwk::JwkSet = serde_json::from_str(&jwt_base64).unwrap();

    if let Some(j) = jwks.find(&header.kid.unwrap()) {
        match &j.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let decoding_key = DecodingKey::from_rsa_components(&rsa.n, &rsa.e).unwrap();
                let mut validation = Validation::new(j.common.algorithm.unwrap());
                validation.validate_exp = false;
                validation.validate_nbf = false;
                let decoded_token = decode::<HashMap<String, serde_json::Value>>(
                    &token.trim(),
                    &decoding_key,
                    &validation,
                )
                .unwrap();
                println!("{:?}", decoded_token);
            }
            _ => unreachable!("this should be a RSA"),
        }
    } else {
        eprintln!("No matching JWK found for the given kid");
    }
}
