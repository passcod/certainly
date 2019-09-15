# certainly

Handy simple tool for common certificate-related operations.

```bash
$ certainly test.example.com test2.example.com foo.local 10.0.200.36
Writing test.example.com.key
Writing test.example.com.crt

$ certainly --inspect test.example.com.crt
[Local]  C=ZZ, O=Certainly, OU=test.example.com from kaydel-ko, CN=test.example.com
Issuer:  C=ZZ, O=Certainly, OU=test.example.com from kaydel-ko, CN=test.example.com

Created on:   Sun Sep 15 01:30:14 2019
Expires on:   Sun Sep 15 01:30:14 2029

Domains:
 DNS: test.example.com
 DNS: test2.example.com
 DNS: foo.local
 IPV4: 10.0.200.36

To see more: $ openssl x509 -text -in test.example.com.crt

$ certainly --inspect twitter.com
[Remote] C=US, ST=California, L=San Francisco, O=Twitter, Inc., OU=syd2, CN=twitter.com
Issuer:  C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA

Chain:
 Subject: C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert SHA2 High Assurance Server CA
 Issuer:  C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert High Assurance EV Root CA

Created on:   Sun May 13 00:00:00 2019
Expires on:   Sun May 10 12:00:00 2020

Domains:
 DNS: twitter.com
 DNS: www.twitter.com

To see more: $ echo Q | openssl s_client twitter.com:443
```


## Install

### Binary download (Windows, Linux, macOS)

Binaries are available [through GitHub Releases](https://github.com/passcod/certainly/releases).

### From source

With Cargo: `cargo install certainly`

### From package manager

#### [Arch Linux (AUR)](https://aur.archlinux.org/packages/certainly-bin)

    yay -S certainly-bin

#### Debian, Ubuntu (deb)

Download the deb file from GitHub Releases.

#### Others

Accepting contributions for more!


## Options

 - `--std` and `--reverse-std` will output both key and certificate to STDOUT instead of writing files.
 - `--double-std` will output the key to STDERR and the certificate to STDOUT instead, so redirection can be used to write or pipe files where needed efficiently. Take care of checking the key is actually formatted properly and not an error message though!

 - `--inspect` outputs terse information about the passed certificate file (or url) and exits.

 - `--make-ca` creates a key/certificate pair suitable for issuing instead. Use with `--ca`.
 - `--ca NAME` signs a certificate with a CA pair instead of self-signing. Provide only the common filename, without the `.crt` and `.key` extensions.

 - `--client` creates client certificates rather than server ones.
 - `--ecdsa` creates p256r1 ECDSA certificates (default).
 - `--ed25519` creates ED25519 certificates.
 - `--rsa` creates 4096-bit RSA certificates (**not for production use**).

See [the man page](./certainly.1.ronn) for more.


## See also

 - [mkcert](https://github.com/FiloSottile/mkcert), a tool specifically for local-CA certificate management.


## Etc

 - Copyright © [Félix Saparelli](https://passcod.name).
 - Licensed under the [Artistic License 2.0](./LICENSE).
