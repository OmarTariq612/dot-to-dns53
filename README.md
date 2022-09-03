## DoT (DNS over TLS) to DNS53

This server relays DNS queries (that comes from a DoT client) to a normal DNS53 server (ex 8.8.8.8:53), in order for it to work you need to have a certificate that is signed by a client-trusted CA.

## REF
* DNS over TLS (rfc 7858): https://www.rfc-editor.org/rfc/rfc7858.html