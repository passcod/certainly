# certainly

The easiest way to create self-signed certificates. Ever.

```bash
$ certainly test.example.com test2.example.com foo.local
Writing test.example.com.key
Writing test.example.com.crt

$ certainly --inspect test.example.com.crt
Self-signed certificate created 2018-09-05 18:52:04 UTC
Expires on 2028-09-05 18:52:04 UTC
Domains:
  - test.example.com
  - test2.example.com
  - foo.local
```


## Install

### Binary download (Windows, Linux, macOS)

Binaries are available [through GitHub Releases](https://github.com/passcod/certainly/releases).

### From source

With Cargo: `cargo install certainly`

### From package manager

#### [Arch Linux (AUR)](https://aur.archlinux.org/packages/certainly-bin)

    yay -S certainly-bin

Accepting contributions for more!


## Options

 - `--std` will output both key and certificate to STDOUT instead of writing files.
 - `--double-std` will output the key to STDERR and the certificate to STDOUT instead, so redirection can be used to write or pipe files where needed efficiently. Take care of checking the key is actually formatted properly and not an error message though!
 - `--inspect` outputs terse information about the passed certificate file and exits.


## Etc

 - Copyright © [Félix Saparelli](https://passcod.name).
 - Licensed under the [Artistic License 2.0](./LICENSE).
