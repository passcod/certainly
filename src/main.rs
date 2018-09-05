extern crate clap;
extern crate openssl;

use clap::{App, Arg};
use std::{io, path::PathBuf};
use openssl::error::ErrorStack;
use openssl::x509::{X509Builder, X509v3Context, X509NameBuilder};
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::ec::{EcGroup, EcKey};
use openssl::pkey::{Private, PKey};
use openssl::hash::MessageDigest;
use openssl::bn::{BigNum, MsbOption};
use openssl::x509::extension::{AuthorityKeyIdentifier as AuthKey, BasicConstraints, KeyUsage,
SubjectAlternativeName, SubjectKeyIdentifier as SubjectKey};
use std::io::Write;
use std::fs::File;

#[derive(Debug)]
enum Ernum {
    Io(io::Error),
    OpenSSL(ErrorStack),
    Other(String),
}

impl From<io::Error> for Ernum {
    fn from(err: io::Error) -> Self {
        Ernum::Io(err)
    }
}

impl From<ErrorStack> for Ernum {
    fn from(err: ErrorStack) -> Self {
        Ernum::OpenSSL(err)
    }
}

impl From<&'static str> for Ernum {
    fn from(err: &str) -> Self {
        Ernum::Other(err.into())
    }
}

fn main() -> Result<(), Ernum> {
    let args = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_HOMEPAGE"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("inspect")
             .long("inspect")
             .value_name("CERTIFICATE")
             .help("Show information about a certificate")
        )
        .arg(Arg::with_name("stdout")
             .long("std")
             .help("Output to stdout instead of writing files")
        )
        .arg(Arg::with_name("stderrout")
             .long("double-std")
             .help("Output the key to stderr and the cert to stdout")
        )
        .arg(Arg::with_name("DOMAIN")
             .multiple(true)
             .help("Every domain this certificate should support")
        )
        .get_matches();

    if args.is_present("inspect") {
        return inspect(args.value_of("inspect").unwrap().into());
    }

    if !args.is_present("DOMAIN") {
        eprintln!("{}", args.usage());
        std::process::exit(2);
    }

    let (name, key, cert) = create(args.values_of("DOMAIN").unwrap().collect())?;
    // unwrap is safe because it will have been caught by is_present()


    if args.is_present("double-std") {
        io::stderr().write(&key)?;
        io::stdout().write(&cert)?;
    } else if args.is_present("std") {
        io::stdout().write(&key)?;
        io::stdout().write(&cert)?;
    } else {
        let keyname = format!("{}.key", name);
        let crtname = format!("{}.crt", name);

        eprintln!("Writing {}", keyname);
        let mut keyfile = File::create(keyname)?;
        keyfile.write(&key)?;

        eprintln!("Writing {}", crtname);
        let mut crtfile = File::create(crtname)?;
        crtfile.write(&cert)?;
    }

    Ok(())
}

fn create(domains: Vec<&str>) -> Result<(String, Vec<u8>, Vec<u8>), Ernum> {
    let name = (*domains.get(0).unwrap()).into();

    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("C", "ZZ")?;
    subject.append_entry_by_text("ST", "AA")?;
    subject.append_entry_by_text("O", "Certainly")?;
    subject.append_entry_by_text("CN", name)?;
    let subject = subject.build();

    let mut cert = X509Builder::new()?;
    cert.set_version(2)?;
    cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
    cert.set_issuer_name(&subject)?;
    cert.set_subject_name(&subject)?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    cert.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    cert.append_extension(BasicConstraints::new().build()?)?;
    cert.append_extension(KeyUsage::new()
        .critical()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()?)?;

    fn ctx(cert: &X509Builder) -> X509v3Context {
        cert.x509v3_context(None, None)
    }

    let subjkey = SubjectKey::new().build(&ctx(&cert))?;
    let authkey = AuthKey::new().keyid(false).issuer(false).build(&ctx(&cert))?;

    let mut san = SubjectAlternativeName::new();
    for dom in domains { san.dns(dom.into()); }
    let san = san.build(&ctx(&cert))?;

    cert.append_extension(subjkey)?;
    cert.append_extension(authkey)?;
    cert.append_extension(san)?;

    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let eckey: EcKey<Private> = EcKey::generate(curve.as_ref())?;
    let pkey = PKey::from_ec_key(eckey)?;
    cert.set_pubkey(pkey.as_ref())?;
    cert.sign(pkey.as_ref(), MessageDigest::sha512())?;

    let cert = cert.build();
    let certpem = cert.to_pem()?;
    let keypem = pkey.private_key_to_pem_pkcs8()?;
    Ok((name.into(), keypem, certpem))
}

fn inspect(filepath: PathBuf) -> Result<(), Ernum> {
    println!("{:?}", filepath);
    Ok(())
}
