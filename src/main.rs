#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![allow(clippy::similar_names)]

use chrono::{format::ParseError as ChronoParseError, Utc};
use clap::{App, Arg, ArgGroup};
use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, KeyPair, RcgenError,
    SignatureAlgorithm,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::{io, path::PathBuf};

#[cfg(feature = "rsa")]
use openssl::error::ErrorStack;
#[cfg(feature = "inspect")]
use openssl::ssl::HandshakeError;
#[cfg(feature = "inspect")]
use std::net::TcpStream;
#[cfg(feature = "inspect")]
use url::ParseError as UrlParseError;

#[derive(Debug)]
pub(crate) enum Ernum {
    Chrono(ChronoParseError),
    Io(io::Error),
    #[cfg(feature = "rsa")]
    OpenSSL(ErrorStack),
    Rcgen(RcgenError),
    #[cfg(feature = "inspect")]
    Tls(HandshakeError<TcpStream>),
    #[cfg(feature = "inspect")]
    Url(UrlParseError),
    Other(String),
}

impl From<io::Error> for Ernum {
    fn from(err: io::Error) -> Self {
        Ernum::Io(err)
    }
}

#[cfg(feature = "rsa")]
impl From<ErrorStack> for Ernum {
    fn from(err: ErrorStack) -> Self {
        Ernum::OpenSSL(err)
    }
}

impl From<RcgenError> for Ernum {
    fn from(err: RcgenError) -> Self {
        Ernum::Rcgen(err)
    }
}

#[cfg(feature = "inspect")]
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

#[cfg(feature = "inspect")]
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
    #[cfg(feature = "rsa")]
    openssl_probe::init_ssl_cert_env_vars();

    let args = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_HOMEPAGE"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
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
        .arg(
            Arg::with_name("ecdsa")
                .long("ecdsa")
                .help("Create an ECDSA P256r1 key and certificate (default)"),
        )
        .arg(
            Arg::with_name("ed25519")
                .long("ed25519")
                .help("Create an ED25519 key and certificate"),
        );

    #[cfg(feature = "rsa")]
    let args = args.arg(
        Arg::with_name("rsa")
            .long("rsa")
            .help("Create an RSA 4096-bit key and certificate"),
    );

    #[cfg(feature = "inspect")]
    let args = args.arg(
        Arg::with_name("inspect")
            .long("inspect")
            .value_name("CERTIFICATE")
            .help("Show information about a certificate"),
    );

    let args = args
        .group(ArgGroup::with_name("algo").args(if cfg!(feature = "rsa") {
            &["ecdsa", "ed25519", "rsa"]
        } else {
            &["ecdsa", "ed25519"]
        }))
        .get_matches();

    if args.is_present("inspect") {
        if cfg!(feature = "inspect") {
            return inspect::inspect(args.value_of("inspect").unwrap().into());
        } else {
            eprintln!("Inspect support is not available, abort");
            std::process::exit(4);
        }
    }

    if !(args.is_present("DOMAIN") || args.is_present("make-ca")) {
        eprintln!("{}", args.usage());
        std::process::exit(2);
    }

    let algo = if args.is_present("rsa") {
        Algo::Rsa
    } else if args.is_present("ed25519") {
        Algo::Ed
    } else {
        Algo::Ec
    };

    if algo == Algo::Rsa && !cfg!(feature = "rsa") {
        eprintln!("RSA support is not available, abort");
        std::process::exit(3);
    }

    let (name, cert, ca) = if args.is_present("make-ca") {
        let name: &str = args.value_of("make-ca").unwrap();
        let cert = makeca(name, algo)?;
        (name.into(), cert, None)
    } else {
        let doms: Vec<&str> = args.values_of("DOMAIN").unwrap().collect();

        if args.is_present("ca") {
            let caname = args.value_of("ca").unwrap();
            let cakey = load_key(format!("{}.key", caname).into())?;
            let cacrt = load_cert(format!("{}.crt", caname).into(), cakey)?;
            let (n, c) = create(&doms, Some(&cacrt), args.is_present("client"), algo)?;
            (n, c, Some(cacrt))
        } else {
            let (n, c) = create(&doms, None, args.is_present("client"), algo)?;
            (n, c, None)
        }
    };

    let key = cert.get_key_pair().serialize_pem();
    let keyb = key.as_bytes();
    let cert = if let Some(ref c) = ca {
        cert.serialize_pem_with_signer(c)
    } else {
        cert.serialize_pem()
    }?;
    let certb = cert.as_bytes();

    if args.is_present("double-std") {
        io::stderr().write_all(keyb)?;
        io::stdout().write_all(certb)?;
    } else if args.is_present("reverse-std") {
        io::stdout().write_all(certb)?;
        io::stdout().write_all(keyb)?;
    } else if args.is_present("std") {
        io::stdout().write_all(keyb)?;
        io::stdout().write_all(certb)?;
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
        keyfile.write_all(keyb)?;

        eprintln!("Writing {}", crtname);
        let mut crtfile = fs.open(crtname)?;
        crtfile.write_all(certb)?;
    }

    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Algo {
    Ec,
    Ed,
    Rsa,
}

impl Algo {
    #[cfg(feature = "rsa")]
    fn rsa_key() -> Result<KeyPair, Ernum> {
        use openssl::{
            pkey::{PKey, Private},
            rsa::Rsa,
        };
        let rsakey: Rsa<Private> = Rsa::generate(4096)?;
        let pem = String::from_utf8(PKey::from_rsa(rsakey)?.private_key_to_pem_pkcs8()?)
            .expect("OpenSSL generated bad PEM, this is not a certainly bug.");
        KeyPair::from_pem(&pem).map_err(Into::into)
    }

    #[cfg(not(feature = "rsa"))]
    fn rsa_key() -> Result<KeyPair, Ernum> {
        unreachable!()
    }

    pub fn key(self) -> Result<KeyPair, Ernum> {
        match self {
            Algo::Ec => KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(Into::into),
            Algo::Ed => KeyPair::generate(&rcgen::PKCS_ED25519).map_err(Into::into),
            Algo::Rsa => Self::rsa_key(),
        }
    }

    pub fn rcgen(self) -> &'static SignatureAlgorithm {
        match self {
            Algo::Ec => &rcgen::PKCS_ECDSA_P256_SHA256,
            Algo::Ed => &rcgen::PKCS_ED25519,
            Algo::Rsa => &rcgen::PKCS_RSA_SHA256,
        }
    }
}

lazy_static::lazy_static! {
    static ref HOSTNAME: std::ffi::OsString = gethostname::gethostname();
}

const OID_ORG_UNIT: &[u64] = &[2, 5, 4, 11];

fn distinguished(name: &str) -> DistinguishedName {
    use rcgen::DnType;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "ZZ");
    dn.push(DnType::OrganizationName, "Certainly");
    dn.push(
        DnType::from_oid(OID_ORG_UNIT),
        format!("{} from {}", name, HOSTNAME.to_string_lossy()),
    );
    dn.push(DnType::CommonName, name);
    dn
}

fn base_cert(name: &str, algo: Algo) -> Result<CertificateParams, Ernum> {
    use chrono::Datelike;
    use rand::Rng;

    let now = Utc::now();
    let mut params = CertificateParams::default();
    params.alg = algo.rcgen();
    params.serial_number = Some(rand::thread_rng().gen());
    params.not_after = now
        .with_year(now.year() + 10)
        .expect("Ten years in the future doesn't exist according to Chrono. Not a certainly bug.");
    params.not_before = now;
    params.distinguished_name = distinguished(name);
    params.key_pair = Some(algo.key()?);
    Ok(params)
}

const OID_KEY_USAGE: &[u64] = &[2, 5, 29, 15];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Usage {
    None,
    Ca,
    Cert,
}

const KEY_USAGE: &[Usage] = &[
    Usage::Cert, // digitalSignature
    Usage::Cert, // nonRepudiation/contentCommitment
    Usage::Cert, // keyEncipherment
    Usage::None,
    Usage::None,
    Usage::Ca, // keyCertSign
    Usage::Ca, // cRLSign
    Usage::None,
    Usage::None,
];

fn key_usage(ca: bool) -> CustomExtension {
    let der = yasna::construct_der(|writer| {
        writer.write_bitvec(
            &KEY_USAGE
                .iter()
                .map(|u| *u == if ca { Usage::Ca } else { Usage::Cert })
                .collect(),
        );
    });

    let mut key_usage = CustomExtension::from_oid_content(OID_KEY_USAGE, der);
    key_usage.set_criticality(true);
    key_usage
}

fn makeca(name: &str, algo: Algo) -> Result<Certificate, Ernum> {
    use rcgen::{BasicConstraints, IsCa};

    let mut params = base_cert(name, algo)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(16));
    params.custom_extensions.push(key_usage(true));

    Certificate::from_params(params).map_err(Into::into)
}

const OID_BASIC: &[u64] = &[2, 5, 29, 19];

fn not_ca() -> CustomExtension {
    let der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bool(false);
        });
    });

    CustomExtension::from_oid_content(OID_BASIC, der)
}

fn create(
    domains: &[&str],
    _ca: Option<&Certificate>,
    is_client: bool,
    algo: Algo,
) -> Result<(String, Certificate), Ernum> {
    use rcgen::{CidrSubnet, ExtendedKeyUsagePurpose, SanType};

    let name = domains[0];
    let mut params = base_cert(name, algo)?;

    params.custom_extensions.push(not_ca());
    params.custom_extensions.push(key_usage(false));
    params.extended_key_usages.push(if is_client {
        ExtendedKeyUsagePurpose::ClientAuth
    } else {
        ExtendedKeyUsagePurpose::ServerAuth
    });
    params.subject_alt_names = domains
        .iter()
        .map(|dom| {
            if let Ok(cidr) = CidrSubnet::from_str(dom) {
                SanType::IpAddress(cidr)
            } else {
                SanType::DnsName(dom.to_string())
            }
        })
        .collect();
    // TODO? add issuer name?

    Ok((name.into(), Certificate::from_params(params)?))
}

fn load_cert(filepath: PathBuf, key: KeyPair) -> Result<Certificate, Ernum> {
    let mut file = File::open(filepath)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;

    let params = CertificateParams::from_ca_cert_pem(&buf, key)?;
    Certificate::from_params(params).map_err(Into::into)
}

fn load_key(filepath: PathBuf) -> Result<KeyPair, Ernum> {
    let mut file = File::open(filepath)?;
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    KeyPair::from_pem(&buf).map_err(Into::into)
}

#[cfg(not(feature = "inspect"))]
mod inspect {
    pub(crate) fn inspect(_: std::path::PathBuf) -> Result<(), super::Ernum> {
        unreachable!()
    }
}

#[cfg(feature = "inspect")]
mod inspect {
    use super::Ernum;
    use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
    use openssl::asn1::Asn1TimeRef;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use openssl::x509::X509;
    use std::fs::File;
    use std::io::Read;
    use std::{net::TcpStream, path::PathBuf};
    use url::Url;

    fn load_cert(filepath: PathBuf) -> Result<X509, Ernum> {
        let mut file = File::open(filepath)?;
        let mut buf = vec![];
        file.read_to_end(&mut buf)?;
        Ok(X509::from_pem(&buf)?)
    }

    fn load_remote_cert(url: &str) -> Result<X509, Ernum> {
        // parse url. try really hard
        let url = Url::parse(url)
            .or_else(|err| Url::parse(&format!("https://{}", url)).map_err(|_| err))?;

        // connect
        let mut connector = SslConnector::builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();
        let stream = TcpStream::connect(url.socket_addrs(|| Some(443))?[0])?;
        let stream = connector.connect(url.host_str().unwrap(), stream)?;

        // get cert
        stream
            .ssl()
            .peer_certificate()
            .ok_or_else(|| "Peer did not present certificate".into())
    }

    fn parse_cert_time(time: &Asn1TimeRef) -> Result<DateTime<Utc>, Ernum> {
        let timestr = format!("{}", time);
        let parsed = NaiveDateTime::parse_from_str(&timestr, "%b %_d %H:%M:%S.%f %Y GMT")
            .or_else(|_| NaiveDateTime::parse_from_str(&timestr, "%b %_d %H:%M:%S %Y GMT"))?;
        Ok(Utc::today().timezone().from_utc_datetime(&parsed))
    }

    pub(crate) fn inspect(filepath: PathBuf) -> Result<(), Ernum> {
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
}
