#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]

use chrono::{format::ParseError as ChronoParseError, DateTime, NaiveDateTime, TimeZone, Utc};
use clap::{App, Arg};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{HandshakeError, SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::extension::{
    AuthorityKeyIdentifier as AuthKey, BasicConstraints, KeyUsage, ExtendedKeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier as SubjectKey,
};
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509Ref, X509};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::{io, net::TcpStream, path::PathBuf};
use url::{ParseError as UrlParseError, Url};

#[derive(Debug)]
enum Ernum {
    Chrono(ChronoParseError),
    Io(io::Error),
    OpenSSL(ErrorStack),
    Tls(HandshakeError<TcpStream>),
    Url(UrlParseError),
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

impl From<ChronoParseError> for Ernum {
    fn from(err: ChronoParseError) -> Self {
        Ernum::Chrono(err)
    }
}

impl From<UrlParseError> for Ernum {
    fn from(err: UrlParseError) -> Self {
        Ernum::Url(err)
    }
}

impl From<&'static str> for Ernum {
    fn from(err: &str) -> Self {
        Ernum::Other(err.into())
    }
}

fn main() -> Result<(), Ernum> {
    // Fix spurious errors because of https://github.com/rust-lang/cargo/issues/3676
    openssl_probe::init_ssl_cert_env_vars();

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
            Arg::with_name("client")
                .long("client")
                .help("Create a client certificate instead of a server one"),
        )
        .arg(
            Arg::with_name("rsa")
                .long("rsa")
                .help("Create an RSA 4096-bit key and certificate instead of ECDSA"),
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
            Arg::with_name("reverse-std")
                .long("reverse-std")
                .help("Output to stdout instead of writing files, with the key last"),
        )
        .arg(
            Arg::with_name("double-std")
                .long("double-std")
                .help("Output the key to stderr and the cert to stdout"),
        )
        .arg(
            Arg::with_name("DOMAIN")
                .multiple(true)
                .help("Every domain or IP this certificate should support"),
        )
        .get_matches();

    if args.is_present("inspect") {
        return inspect(args.value_of("inspect").unwrap().into());
    }

    if !(args.is_present("DOMAIN") || args.is_present("make-ca")) {
        eprintln!("{}", args.usage());
        std::process::exit(2);
    }

    let rsa = args.is_present("rsa");

    let (name, key, cert) = if args.is_present("make-ca") {
        let name: &str = args.value_of("make-ca").unwrap();
        let (key, cert) = makeca(name, rsa)?;
        (name.into(), key, cert)
    } else {
        let doms = args.values_of("DOMAIN").unwrap().collect();

        if args.is_present("ca") {
            let caname = args.value_of("ca").unwrap();
            let cakey = load_key(format!("{}.key", caname).into())?;
            let cacrt = load_cert(format!("{}.crt", caname).into())?;
            create(
                doms,
                Some((cakey.as_ref(), cacrt.as_ref())),
                args.is_present("client"),
                rsa,
            )?
        } else {
            create(doms, None, args.is_present("client"), rsa)?
        }
    };

    if args.is_present("double-std") {
        io::stderr().write_all(&key)?;
        io::stdout().write_all(&cert)?;
    } else if args.is_present("reverse-std") {
        io::stdout().write_all(&cert)?;
        io::stdout().write_all(&key)?;
    } else if args.is_present("std") {
        io::stdout().write_all(&key)?;
        io::stdout().write_all(&cert)?;
    } else {
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;

        let keyname = format!("{}.key", name);
        let crtname = format!("{}.crt", name);

        let mut fs = OpenOptions::new();
        fs.write(true).create(true).truncate(true);

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

fn distinguished(org: &str, name: &str) -> Result<X509Name, Ernum> {
    let mut dn = X509NameBuilder::new()?;
    dn.append_entry_by_text("C", "ZZ")?;
    dn.append_entry_by_text("ST", "AA")?;
    dn.append_entry_by_text("O", &format!("Certainly {}", org))?;
    dn.append_entry_by_text("CN", name)?;
    Ok(dn.build())
}

fn base_cert(name: &str, ca: Option<(&PKeyRef<Private>, &X509Ref)>) -> Result<X509Builder, Ernum> {
    let mut cert = X509Builder::new()?;
    cert.set_version(2)?;
    cert.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    cert.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
    cert.set_subject_name(distinguished("Subjecting", name)?.as_ref())?;

    let cacert = ca.map(|(_, c)| c);
    if let Some(caert) = cacert {
        cert.set_issuer_name(caert.subject_name())?;
    } else {
        cert.set_issuer_name(distinguished("Issuing", name)?.as_ref())?;
    };

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

fn base_ecc_key() -> Result<PKey<Private>, Ernum> {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let eckey: EcKey<Private> = EcKey::generate(curve.as_ref())?;
    Ok(PKey::from_ec_key(eckey)?)
}

fn base_rsa_key() -> Result<PKey<Private>, Ernum> {
    let rsakey: Rsa<Private> = Rsa::generate(4096)?;
    Ok(PKey::from_rsa(rsakey)?)
}

fn makeca(name: &str, rsa: bool) -> Result<(Vec<u8>, Vec<u8>), Ernum> {
    let mut cert = base_cert(name, None)?;

    cert.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let pkey = if rsa {
        base_rsa_key()
    } else {
        base_ecc_key()
    }?;

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
    is_client: bool,
    rsa: bool,
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

    let mut ekr = ExtendedKeyUsage::new();
    if is_client {
        ekr.client_auth();
    } else {
        ekr.server_auth();
    }
    let ekr = ekr.build()?;
    cert.append_extension(ekr)?;

    let mut san = SubjectAlternativeName::new();
    for dom in domains {
        use std::net::{Ipv4Addr, Ipv6Addr};

        if dom.parse::<Ipv4Addr>().is_ok() || dom.parse::<Ipv6Addr>().is_ok() {
            san.ip(dom);
        } else {
            san.dns(dom);
        }
    }
    let san = san.build(&cert.x509v3_context(ca.map(|(_, c)| c), None))?;
    cert.append_extension(san)?;

    let pkey = if rsa {
        base_rsa_key()
    } else {
        base_ecc_key()
    }?;

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
    let url =
        Url::parse(url).or_else(|err| Url::parse(&format!("https://{}", url)).map_err(|_| err))?;

    // connect
    let mut connector = SslConnector::builder(SslMethod::tls())?;
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();
    let stream = TcpStream::connect(url.with_default_port(|_| Ok(443))?)?;
    let stream = connector.connect(url.host_str().unwrap(), stream)?;

    // get cert
    stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "Peer did not present certificate".into())
}

fn parse_cert_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, Ernum> {
    let timestr = format!("{}", time);
    let parsed = NaiveDateTime::parse_from_str(&timestr, "%b %_d %H:%M:%S %Y GMT")?;
    Ok(Utc::today().timezone().from_utc_datetime(&parsed))
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
            },
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

    println!("Created on:   {}", parse_cert_time(cert.not_before())?);
    let expiry = parse_cert_time(cert.not_after())?;
    let expired = Utc::now() > expiry;
    println!("Expire{} on:   {}", if expired { 'd' } else { 's' }, expiry);

    match cert.subject_alt_names() {
        None => {
            if let Some(name) = cname {
                println!("Domains:\n - {}", name);
            } else {
                println!("No domains???");
            }
        }
        Some(alts) => {
            println!("Domains:");
            for alt in alts {
                if let Some(dns) = alt.dnsname() {
                    println!(" DNS: {}", dns);
                } else if let Some(ip) = alt.ipaddress() {
                    use std::convert::TryFrom;
                    use std::net::{Ipv4Addr, Ipv6Addr};

                    if let Ok(octets) = <[u8; 16]>::try_from(ip) {
                        println!(" IPV6: {}", Ipv6Addr::from(octets));
                    } else if let Ok(octets) = <[u8; 4]>::try_from(ip) {
                        println!(" IPV4: {}", Ipv4Addr::from(octets));
                    }
                } else if let Some(uri) = alt.uri() {
                    println!(" URI: {}", uri);
                } else if let Some(email) = alt.email() {
                    println!(" EMAIL: {}", email);
                }
            }
        }
    };

    Ok(())
}
