#![forbid(unsafe_code)]
#![deny(clippy::pedantic)]
#![deny(clippy::nursery)]
#![allow(clippy::similar_names)]

use chrono::{format::ParseError as ChronoParseError, Utc};
use clap::{App, Arg, ArgGroup};
use nom::Err as NomErr;
use rcgen::{
    Certificate, CertificateParams, CustomExtension, DistinguishedName, KeyPair, RcgenError,
    SignatureAlgorithm,
};
use rsa::errors::Error as RsaError;
use rustls_connector::{rustls, webpki, HandshakeError, RustlsConnector};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::{io, path::PathBuf};
use time::Tm;
use url::ParseError as UrlParseError;
use x509_parser::{
    error::{PEMError, X509Error},
    parse_x509_der,
    pem::pem_to_der,
    X509Certificate,
};

#[derive(Debug)]
pub(crate) enum Ernum {
    Chrono(ChronoParseError),
    Io(io::Error),
    Rcgen(RcgenError),
    Tls(Box<HandshakeError<TcpStream>>),
    Url(UrlParseError),
    X509(NomErr<X509Error>),
    Pem(NomErr<PEMError>),
    Rsa(RsaError),
    Other(String),
}

impl From<io::Error> for Ernum {
    fn from(err: io::Error) -> Self {
        Ernum::Io(err)
    }
}

impl From<RcgenError> for Ernum {
    fn from(err: RcgenError) -> Self {
        Ernum::Rcgen(err)
    }
}

impl From<HandshakeError<TcpStream>> for Ernum {
    fn from(err: HandshakeError<TcpStream>) -> Self {
        Ernum::Tls(Box::new(err))
    }
}

impl From<ChronoParseError> for Ernum {
    fn from(err: ChronoParseError) -> Self {
        Ernum::Chrono(err)
    }
}

impl From<NomErr<X509Error>> for Ernum {
    fn from(err: NomErr<X509Error>) -> Self {
        Ernum::X509(err)
    }
}

impl From<NomErr<PEMError>> for Ernum {
    fn from(err: NomErr<PEMError>) -> Self {
        Ernum::Pem(err)
    }
}

impl From<UrlParseError> for Ernum {
    fn from(err: UrlParseError) -> Self {
        Ernum::Url(err)
    }
}

impl From<RsaError> for Ernum {
    fn from(err: RsaError) -> Self {
        Ernum::Rsa(err)
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
        )
        .arg(
            Arg::with_name("rsa")
                .long("rsa")
                .help("Create an RSA 4096-bit key and certificate"),
        )
        .group(ArgGroup::with_name("algo").args(&["ecdsa", "ed25519", "rsa"]))
        .get_matches();

    if args.is_present("inspect") {
        return inspect(args.value_of("inspect").unwrap().into());
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

const RSA_BITS: usize = 4096;
const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113_549, 1, 1, 1];

impl Algo {
    fn rsa_key() -> Result<KeyPair, Ernum> {
        use num_bigint::{BigInt, BigUint};
        use num_bigint_dig::{BigUint as BigUintDig, ModInverse};
        use rand::rngs::OsRng;
        use rsa::{PublicKey, RSAPrivateKey};
        use std::convert::TryFrom;

        let mut rng = OsRng::new().expect("no secure randomness available");
        let key = RSAPrivateKey::new(&mut rng, RSA_BITS)?;

        let modulus = key.n();
        let public_exponent = key.e();
        let private_exponent = key.d();
        let first_prime = &key.primes()[0];
        let second_prime = &key.primes()[1];
        let first_exponent = private_exponent % (first_prime - &BigUintDig::from(1_u8));
        let second_exponent = private_exponent % (second_prime - &BigUintDig::from(1_u8));
        let coefficient = second_prime.mod_inverse(first_prime).unwrap();

        let modulus = BigUint::from_bytes_le(&modulus.to_bytes_le());
        let public_exponent = BigUint::from_bytes_le(&public_exponent.to_bytes_le());
        let private_exponent = BigUint::from_bytes_le(&private_exponent.to_bytes_le());
        let first_prime = BigUint::from_bytes_le(&first_prime.to_bytes_le());
        let second_prime = BigUint::from_bytes_le(&second_prime.to_bytes_le());
        let first_exponent = BigUint::from_bytes_le(&first_exponent.to_bytes_le());
        let second_exponent = BigUint::from_bytes_le(&second_exponent.to_bytes_le());
        let coefficient = BigInt::from_signed_bytes_le(&coefficient.to_signed_bytes_le());

        let keyder = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(0);
                writer.next().write_biguint(&modulus);
                writer.next().write_biguint(&public_exponent);
                writer.next().write_biguint(&private_exponent);
                writer.next().write_biguint(&first_prime);
                writer.next().write_biguint(&second_prime);
                writer.next().write_biguint(&first_exponent);
                writer.next().write_biguint(&second_exponent);
                writer.next().write_bigint(&coefficient);
            })
        });

        let pk8 = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(0);
                writer.next().write_sequence(|writer| {
                    writer.next().write_oid(&OID_RSA_ENCRYPTION.to_vec().into());
                    writer.next().write_null();
                });
                writer.next().write_bytes(&keyder);
            })
        });

        KeyPair::try_from(pk8.as_slice()).map_err(Into::into)
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
    use rcgen::{ExtendedKeyUsagePurpose, SanType};
    use std::net::IpAddr;
    use std::str::FromStr;

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
            if let Ok(ip) = IpAddr::from_str(dom) {
                SanType::IpAddress(ip)
            } else {
                SanType::DnsName(dom.to_string())
            }
        })
        .collect();

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

pub struct NoCertificateVerification;

impl rustls::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef<'_>,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedCert {
    issuer: String,
    subject: String,
    not_before: Tm,
    not_after: Tm,
    names: Vec<GeneralName>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GeneralName {
    Email(String),
    Dns(String),
    Ip(Vec<u8>),
    Uri(String),
    Unknown,
}

const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";

impl ParsedCert {
    fn parse(cert: X509Certificate<'_>) -> Self {
        let tbs = cert.tbs_certificate;

        let mut san = None;
        for ext in tbs.extensions {
            if ext.oid == OID_SUBJECT_ALT_NAME.parse().unwrap() {
                san = Some(ext.value);
                break;
            }
        }

        let names = san
            .and_then(|san| {
                yasna::parse_ber(san, |reader| {
                    reader.collect_sequence_of(|reader| {
                        let tagged = reader.read_tagged_der()?;
                        let num = tagged.tag().tag_number;
                        Ok(match num {
                            1 | 2 | 6 => {
                                let val = std::str::from_utf8(tagged.value()).unwrap().into();
                                match num {
                                    1 => GeneralName::Email(val),
                                    2 => GeneralName::Dns(val),
                                    6 => GeneralName::Uri(val),
                                    _ => unreachable!(),
                                }
                            }
                            7 => GeneralName::Ip(tagged.value().into()),
                            _ => GeneralName::Unknown,
                        })
                    })
                })
                .ok()
            })
            .unwrap_or_default();

        Self {
            issuer: tbs.issuer.to_string(),
            subject: tbs.subject.to_string(),
            not_before: tbs.validity.not_before,
            not_after: tbs.validity.not_after,
            names,
        }
    }

    pub fn load_local(filepath: PathBuf) -> Result<Self, Ernum> {
        let mut file = File::open(filepath)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let (_, der) = pem_to_der(&buf)?;
        let (_, cert) = parse_x509_der(&der.contents)?;
        Ok(Self::parse(cert))
    }

    pub fn load_remote(url: &str) -> Result<Vec<Self>, Ernum> {
        use rustls::Session;
        use std::sync::Arc;
        use url::Url;

        // parse url. try really hard
        let url = Url::parse(url)
            .or_else(|err| Url::parse(&format!("https://{}", url)).map_err(|_| err))?;

        // disable verification
        let mut config = rustls::ClientConfig::new();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
        let connector = RustlsConnector::new(config);

        // connect
        let stream = TcpStream::connect(url.socket_addrs(|| Some(443))?[0])?;
        let stream = connector.connect(url.host_str().unwrap(), stream)?;

        // get certs
        let chain = stream
            .sess
            .get_peer_certificates()
            .ok_or_else(|| Ernum::Other("no certificate in chain".into()))?;

        // decode certs
        let mut certs = Vec::with_capacity(chain.len());
        for raw in chain {
            let (_, cert) = parse_x509_der(&raw.0)?;
            certs.push(Self::parse(cert));
        }

        Ok(certs)
    }
}

fn inspect(filepath: PathBuf) -> Result<(), Ernum> {
    let mut is_remote = false;
    let maybe_url = filepath.clone();
    let maybe_url = maybe_url.to_str().unwrap();
    let mut certs = if filepath.starts_with("https://") {
        is_remote = true;
        ParsedCert::load_remote(maybe_url)?
    } else {
        match ParsedCert::load_local(filepath) {
            Ok(cert) => vec![cert],
            Err(filerr) => match ParsedCert::load_remote(maybe_url) {
                Ok(certs) => {
                    is_remote = true;
                    certs
                }
                Err(err) => {
                    eprintln!("{:?}", filerr);
                    return Err(err);
                }
            },
        }
    };

    let cert = certs.remove(0);
    let rest = certs;

    println!(
        "{} {}",
        if is_remote { "[Remote]" } else { "[Local] " },
        cert.subject
    );
    println!("Issuer:  {}", cert.issuer);

    if !rest.is_empty() {
        println!("\nChain:");
    }
    for c in &rest {
        println!(" Subject: {}\n Issuer:  {}\n", c.subject, c.issuer);
    }

    if rest.is_empty() {
        println!();
    }
    println!("Created on:   {}", cert.not_before.asctime());
    let expired = time::now() > cert.not_after;
    println!(
        "Expire{} on:   {}",
        if expired { 'd' } else { 's' },
        cert.not_after.asctime()
    );

    if !cert.names.is_empty() {
        println!("\nDomains:");
    }

    let mut others = 0;
    for name in cert.names {
        match name {
            GeneralName::Dns(dns) => println!(" DNS: {}", dns),
            GeneralName::Ip(ip) => {
                use std::convert::TryFrom;
                use std::net::{Ipv4Addr, Ipv6Addr};

                let bytes: &[u8] = &ip;
                if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
                    println!(" IPV6: {}", Ipv6Addr::from(octets));
                } else if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
                    println!(" IPV4: {}", Ipv4Addr::from(octets));
                }
            }
            GeneralName::Email(mail) => println!(" EMAIL: {}", mail),
            GeneralName::Uri(uri) => println!(" URL: {}", uri),
            _ => {
                others += 1;
            }
        }
    }

    if others > 0 {
        println!(" ({} of other types)", others);
    }

    print!("\nTo see more: $ ");
    if is_remote {
        println!("echo Q | openssl s_client {}:443", maybe_url);
    } else {
        println!("openssl x509 -text -in {}", maybe_url);
    }

    Ok(())
}
