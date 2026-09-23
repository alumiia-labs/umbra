# FCM test key

`test-key.pem` is an RSA key of 2048 bits in PKCS #8, made for the tests of
the FCM sender of the NDR (`crates/umbra-relay/src/fcm.rs`). It is no key of a
Google service account, no party trusts it, and it is in this repository
because it protects nothing. A test writes a service account file around it
with a token endpoint on loopback.
