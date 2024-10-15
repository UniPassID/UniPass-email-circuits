# UniPass-email-circuits

UniPass-Email-circuits consists of two parts: 
+ a standard Plonk library is implemented. `plookup-sha256`
+ and based on this library, a zero-knowledge proof processing circuit for email and openid is implemented. `prover`

test

```sh
cargo test --release -- --nocapture
```