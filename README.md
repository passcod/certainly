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

Nothing yet, but accepting contributions!


## Options

TBD


## Etc

- Copyright © [Félix Saparelli](https://passcod.name).
- Licensed under the [Artistic License 2.0](./LICENSE).
