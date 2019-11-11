Rudimentary Acme(V2) client with associated DNS server, HTTP challenge server, and HTTPS certificate server.          

The Automatic Certificate Management Environment (ACME) protocol is a communications protocol for automating interactions between certificate authorities and their users' web servers, allowing the automated deployment of public key infrastructure at very low cost. It was designed by the Internet Security Research Group (ISRG) for their Let's Encrypt service.

The protocol, based on passing JSON-formatted messages over HTTPS, has been published as an Internet Standard in RFC 8555 (https://tools.ietf.org/html/rfc8555).

#### Command-line arguments                                                                                                                                                                                                                   
##### Positional Arguments
- Challenge type (required, {dns01 | http01}) indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dns-01 and http-01 challenges, respectively.
##### Keyword Arguments
- --dir DIR_URL (required) DIR URL is the directory URL of the ACME server that should be used.
- --record IPv4 ADDRESS (required) IPv4 ADDRESS is the IPv4 address which must be returned by your DNS server for all A-record queries.
- --domain DOMAIN (required, multiple) DOMAIN is the domain for which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net.
- --revoke (optional) If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate.

Example Consider the following invocation of run: 

    python3 main.py dns01 --dir https://example.com/dir --record 1.2.3.4  --domain example.com --domain *.example.com
