# UniPass-email-circuits

UniPass-Email-circuits consists of two parts: 
+ a standard Plonk library is implemented. `plookup-sha256`
+ and based on this library, a zero-knowledge proof processing circuit for email and openid is implemented. `prover`


## Circiuts

+ base64: The circuit verifies the correctness of the Base64 encoding.
+ circuit_1024: The circuit verifies the correctness of the hidden email address of the email, and the upper limit of the email length is 1024 bytes.
+ circuit_2048: The circuit verifies the correctness of the hidden email address of the email, and the upper limit of the email length is 2048 bytes.
+ circuit_2048_triple: The circuit verifies the correctness of the hidden email address of the email. The upper limit of the email length is 1024 bytes. Three emails can be aggregated for verification at the same time.

## test

```sh
cargo test --release -- --nocapture
```