# const-pki-types

Converting X.509 certificates to the TrustAnchor in rustls-pki-types at compile time

The usage is same as [webpki::anchor_from_trusted_cert](https://docs.rs/rustls-webpki/latest/webpki/fn.anchor_from_trusted_cert.html)

## Converting PEM certificate to TrustAnchor?

You may also need [const-decoder::decode](https://docs.rs/const-decoder/0.4.0/const_decoder/macro.decode.html#usage-with-pem)
