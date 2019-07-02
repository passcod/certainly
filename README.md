# certainly

~~The easiest way to create self-signed certificates. Ever.~~

Handy simple tool for common certificate-related operations.

```bash
$ certainly test.example.com test2.example.com foo.local 10.0.200.36
Writing test.example.com.key
Writing test.example.com.crt

$ certainly --inspect test.example.com.crt
Self-signed certificate
Created on:   2018-09-06 01:30:45 UTC
Expires on:   2028-09-03 01:30:45 UTC
Domains:
 DNS: test.example.com
 DNS: test2.example.com
 DNS: foo.local
 IP: 10.0.200.36

$ certainly --inspect twitter.com
Certificate signed by DigiCert SHA2 High Assurance Server CA
Created on:   2018-07-17 00:00:00 UTC
Expires on:   2019-08-22 12:00:00 UTC
Domains:
 DNS: twitter.com
 DNS: www.twitter.com
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
 - `--rsa` creates 4096-bit RSA certificates instead of 256-bit ECDSA ones.

See [the man page](./certainly.1.ronn) for more.


## See also

 - [mkcert](https://github.com/FiloSottile/mkcert), a tool specifically for local-CA certificate management.


## Etc

 - Copyright © [Félix Saparelli](https://passcod.name).
 - Licensed under the [Artistic License 2.0](./LICENSE).
