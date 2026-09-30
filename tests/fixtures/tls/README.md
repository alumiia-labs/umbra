# Test certificates

`ca.pem` is a test authority, and `leaf.pem` with `leaf.key` is a server
certificate for `localhost` under it. The key of the authority was deleted
after it signed the leaf, thus it signs nothing more. No shipped client
trusts this authority: a test gives `ca.pem` to
`umbra_transport::native::tls_config_with_roots`.

`../devnet` holds the settings of seven relays, the directory, the NDR, and
the test authority for `scripts/devnet.sh`. Their
secrets are in this repository, thus that network protects nothing. The
debug build of the Android app trusts `ca.pem` and dials that network, and
the release build holds neither.
