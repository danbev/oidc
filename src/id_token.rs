use jsonwebtoken::jwk::AlgorithmParameters;
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, Validation};
use std::collections::HashMap;
use std::fs;

fn main() {
    let token = fs::read_to_string("token").unwrap();
    let token = token.trim();
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
                    &token,
                    &decoding_key,
                    &validation,
                )
                .unwrap();
                println!("claims: {:?}", decoded_token.claims);
                println!("sub: {:?}", decoded_token.claims.get("sub").unwrap());
                println!(
                    "job_workflow_ref: {:?}",
                    decoded_token.claims.get("job_workflow_ref").unwrap()
                );
            }
            _ => unreachable!("this should be a RSA"),
        }
    } else {
        eprintln!("No matching JWK found for the given kid");
    }
}
