# get-certificate-trustchain
Gets a list of PEM encoded certificates to use with the 
`ssl_trusted_certificate` parameter in nginx.

When using OCSP stapling with nginx, a file with a list of PEM encoded 
certificates should be added to the `ssl_trusted_certificate` parameter. 
Otherwise the `ssl_stapling_verify` parameter can't be enabled.

This program reads your certificate and any intermediate certificates in it. 
It will use the `CA Issuers - URI` field for any remaining certificates in 
the chain. When the field is empty it is assumed the root is reached.