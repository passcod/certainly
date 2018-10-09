# certainly

~~The easiest way to create self-signed certificates. Ever.~~

Handy simple tool for common certificate-related operations.

```bash
$ certainly test.example.com test2.example.com foo.local
Writing test.example.com.key
Writing test.example.com.crt

$ certainly --inspect test.example.com.crt
Self-signed certificate
Created on:   Sep  6 01:30:45 2018 GMT
Expires on:   Sep  3 01:30:45 2028 GMT
Domains:
 - test.example.com
 - test2.example.com
 - foo.local

$ certainly --inspect twitter.com
Certificate signed by DigiCert SHA2 High Assurance Server CA
Created on:   Jul 17 00:00:00 2018 GMT
Expires on:   Jul 22 12:00:00 2019 GMT
Domains:
 - twitter.com
 - www.twitter.com
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

 - `--std` will output both key and certificate to STDOUT instead of writing files.
 - `--double-std` will output the key to STDERR and the certificate to STDOUT instead, so redirection can be used to write or pipe files where needed efficiently. Take care of checking the key is actually formatted properly and not an error message though!

 - `--inspect` outputs terse information about the passed certificate file (or url) and exits.

 - `--make-ca` creates a key/certificate pair suitable for issuing instead. Use with `--ca`.
 - `--ca NAME` signs a certificate with a CA pair instead of self-signing. Provide only the common filename, without the `.crt` and `.key` extensions.

See [the man page](./certainly.1.ronn) for more.


## Etc

 - Copyright © [Félix Saparelli](https://passcod.name).
 - Licensed under the [Artistic License 2.0](./LICENSE).
