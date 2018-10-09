#![forbid(unsafe_code)]
#![cfg_attr(feature = "cargo-clippy", deny(clippy_pedantic))]
#![cfg_attr(feature = "cargo-clippy", allow(similar_names))]

extern crate clap;
extern crate openssl;
extern crate url;

use clap::{App, Arg};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::ssl::{HandshakeError, SslMethod, SslConnector};
use openssl::x509::extension::{
    AuthorityKeyIdentifier as AuthKey, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier as SubjectKey,
};
use openssl::x509::{X509, X509Builder, X509NameBuilder, X509Ref};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::{io, net::TcpStream, path::PathBuf};
use url::{Url, ParseError};

#[derive(Debug)]
enum Ernum {
    Io(io::Error),
    OpenSSL(ErrorStack),
    Tls(HandshakeError<TcpStream>),
    Url(ParseError),
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

impl From<HandshakeError<TcpStream>> for Ernum {
    fn from(err: HandshakeError<TcpStream>) -> Self {
        Ernum::Tls(err)
    }
}

impl From<ParseError> for Ernum {
    fn from(err: ParseError) -> Self {
        Ernum::Url(err)
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
        .arg(
            Arg::with_name("inspect")
                .long("inspect")
                .value_name("CERTIFICATE")
                .help("Show information about a certificate"),
        )
        .arg(
            Arg::with_name("make-ca")
                .long("make-ca")
                .value_name("NAME")
                .help("Create a CA cert and key suitable for signing"),
        )
        .arg(
            Arg::with_name("ca")
                .long("ca")
                .value_name("NAME")
                .help("Issue a certificate using a CA cert and key"),
        )
        .arg(
            Arg::with_name("std")
                .long("std")
                .help("Output to stdout instead of writing files"),
        )
        .arg(
            Arg::with_name("double-std")
                .long("double-std")
                .help("Output the key to stderr and the cert to stdout"),
        )
        .arg(
            Arg::with_name("DOMAIN")
                .multiple(true)
                .help("Every domain this certificate should support"),
        )
        .get_matches();

    if args.is_present("inspect") {
        return inspect(args.value_of("inspect").unwrap().into());
    }

    if !(args.is_present("DOMAIN") || args.is_present("make-ca")) {
        eprintln!("{}", args.usage());
        std::process::exit(2);
    }

    let (name, key, cert) = if args.is_present("make-ca") {
        let name: &str = args.value_of("make-ca").unwrap();
        let (key, cert) = makeca(name)?;
        (name.into(), key, cert)
    } else {
        let doms = args.values_of("DOMAIN").unwrap().collect();

        if args.is_present("ca") {
            let caname = args.value_of("ca").unwrap();
            let cakey = load_key(format!("{}.key", caname).into())?;
            let cacrt = load_cert(format!("{}.crt", caname).into())?;
            create(doms, Some((cakey.as_ref(), cacrt.as_ref())))?
        } else {
            create(doms, None)?
        }
    };

    if args.is_present("double-std") {
        io::stderr().write_all(&key)?;
        io::stdout().write_all(&cert)?;
    } else if args.is_present("std") {
        io::stdout().write_all(&key)?;
        io::stdout().write_all(&cert)?;
    } else {
        let keyname = format!("{}.key", name);
        let crtname = format!("{}.crt", name);

        let mut fs = OpenOptions::new();
        fs.write(true).create(true).truncate(true);

        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(unix)]
        fs.mode(0o600);

        eprintln!("Writing {}", keyname);
        let mut keyfile = fs.open(keyname)?;
        keyfile.write_all(&key)?;

        eprintln!("Writing {}", crtname);
        let mut crtfile = fs.open(crtname)?;
        crtfile.write_all(&cert)?;
    }

    Ok(())
}

fn base_cert(name: &str, ca: Option<(&PKeyRef<Private>, &X509Ref)>) -> Result<X509Builder, Ernum> {
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
    cert.set_subject_name(&subject)?;

    let cacert = ca.map(|(_, c)| c);
    cert.set_issuer_name(if let Some(cert) = cacert {
        cert.subject_name()
    } else {
        &subject
    })?;

    let mut serial = BigNum::new()?;
    serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
    cert.set_serial_number(serial.to_asn1_integer()?.as_ref())?;

    let subjkey = SubjectKey::new().build(&cert.x509v3_context(cacert, None))?;
    let authkey = AuthKey::new()
        .keyid(false)
        .issuer(false)
        .build(&cert.x509v3_context(cacert, None))?;

    cert.append_extension(subjkey)?;
    cert.append_extension(authkey)?;

    Ok(cert)
}

fn base_key() -> Result<PKey<Private>, Ernum> {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let eckey: EcKey<Private> = EcKey::generate(curve.as_ref())?;
    Ok(PKey::from_ec_key(eckey)?)
}

fn makeca(name: &str) -> Result<(Vec<u8>, Vec<u8>), Ernum> {
    let mut cert = base_cert(name, None)?;

    cert.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let pkey = base_key()?;
    cert.set_pubkey(pkey.as_ref())?;
    cert.sign(pkey.as_ref(), MessageDigest::sha512())?;

    let cert = cert.build();
    let certpem = cert.to_pem()?;
    let keypem = pkey.private_key_to_pem_pkcs8()?;
    Ok((keypem, certpem))
}

fn create(
    domains: Vec<&str>,
    ca: Option<(&PKeyRef<Private>, &X509Ref)>,
) -> Result<(String, Vec<u8>, Vec<u8>), Ernum> {
    let name = domains[0];
    let mut cert = base_cert(name, ca)?;

    cert.append_extension(BasicConstraints::new().build()?)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let mut san = SubjectAlternativeName::new();
    for dom in domains {
        san.dns(dom);
    }
    let san = san.build(&cert.x509v3_context(ca.map(|(_, c)| c), None))?;
    cert.append_extension(san)?;

    let pkey = base_key()?;
    cert.set_pubkey(pkey.as_ref())?;
    cert.sign(
        if let Some((cakey, _)) = ca {
            cakey
        } else {
            pkey.as_ref()
        },
        MessageDigest::sha512(),
    )?;

    let cert = cert.build();
    let certpem = cert.to_pem()?;
    let keypem = pkey.private_key_to_pem_pkcs8()?;
    Ok((name.into(), keypem, certpem))
}

fn load_cert(filepath: PathBuf) -> Result<X509, Ernum> {
    let mut file = File::open(filepath)?;
    let mut buf = vec![];
    file.read_to_end(&mut buf)?;
    Ok(X509::from_pem(&buf)?)
}

fn load_key(filepath: PathBuf) -> Result<PKey<Private>, Ernum> {
    let mut file = File::open(filepath)?;
    let mut buf = vec![];
    file.read_to_end(&mut buf)?;
    Ok(PKey::private_key_from_pem(&buf)?)
}

fn load_remote_cert(url: &str) -> Result<X509, Ernum> {
    // parse url. try really hard
    let url = Url::parse(url)
        .or_else(|err| Url::parse(&format!("https://{}", url)).map_err(|_| err))?;

    // connect
    let connector = SslConnector::builder(SslMethod::tls())?.build();
    let stream = TcpStream::connect(url.with_default_port(|_| Ok(443))?)?;
    let stream = connector.connect(url.host_str().unwrap(), stream)?;

    // get cert
    stream.ssl().peer_certificate().ok_or_else(||
        "Peer did not present certificate".into()
    )
}

fn inspect(filepath: PathBuf) -> Result<(), Ernum> {
    let maybe_url = filepath.clone();
    let maybe_url = maybe_url.to_str().unwrap();
    let cert = if filepath.starts_with("https://") {
        load_remote_cert(maybe_url)?
    } else {
        match load_cert(filepath) {
            Ok(cert) => cert,
            Err(filerr) => match load_remote_cert(maybe_url) {
                Ok(cert) => cert,
                Err(err) => {
                    eprintln!("{:?}", filerr);
                    return Err(err);
                }
            }
        }
    };

    let mut cname = None;
    let mut subjname: Vec<String> = vec![];
    for subj in cert.subject_name().entries() {
        let name = subj.object().nid().long_name()?;
        let data = subj.data().as_utf8()?;
        subjname.push(name.to_string());
        subjname.push(data.to_string());
        if name == "commonName" {
            cname = Some(data);
        }
    }

    let mut iname = None;
    let mut issuname: Vec<String> = vec![];
    for issu in cert.issuer_name().entries() {
        let name = issu.object().nid().long_name()?;
        let data = issu.data().as_utf8()?;
        issuname.push(name.to_string());
        issuname.push(data.to_string());
        if name == "commonName" {
            iname = Some(data);
        }
    }

    if subjname == issuname {
        println!("Self-signed certificate");
    } else if let Some(name) = iname {
        println!("Certificate signed by {}", name);
    } else {
        println!("Certificate (signed)");
    }

    println!("Created on:   {}", cert.not_before());
    println!("Expires on:   {}", cert.not_after());

    match cert.subject_alt_names() {
        None => if let Some(name) = cname {
            println!("Domains:\n - {}", name);
        } else {
            println!("No domains???");
        },
        Some(alts) => {
            println!("Domains:");
            for alt in alts {
                if let Some(dns) = alt.dnsname() {
                    println!(" - {}", dns);
                }
            }
        }
    };

    Ok(())
}
