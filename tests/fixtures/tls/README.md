# Test certificates

`ca.pem` is a test authority, and `leaf.pem` with `leaf.key` is a server
certificate for `localhost` under it. The key of the authority was deleted
after it signed the leaf, thus it signs nothing more. No shipped client
trusts this authority: a test gives `ca.pem` to
`umbra_transport::native::tls_config_with_roots`.
