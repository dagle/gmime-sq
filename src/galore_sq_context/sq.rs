use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::File, io::{self, Read, Write}, time::SystemTime, str::FromStr, hash::Hash, ptr::hash, borrow::Borrow, future::poll_fn};
 
extern crate sequoia_openpgp as openpgp;
use glib::Cast;
use gmime::{traits::{SignatureListExt, SignatureExt, CertificateExt, DecryptResultExt, CertificateListExt}, PubKeyAlgo, DigestAlgo, DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, armor, types::{SignatureType, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, SymmetricAlgorithm}, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder, VerificationResult, DecryptorBuilder, DecryptionHelper}, KeyID, cert::{prelude::ValidErasedKeyAmalgamation, amalgamation::ValidAmalgamation, ValidCert}, crypto::{self, KeyPair}, fmt::hex, packet::key::{UnspecifiedRole, PublicParts}};
use openpgp::serialize::stream::*;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::Serialize;
use anyhow::Context;

use openpgp::{cert::{
        Cert,
        CertParser,
    }, packet::UserID};

use openpgp::parse::Parse;

use super::imp::SqContext;

// TODO we should do more than this, what should we match on
fn cmp_opt<T: PartialEq>(o1: Option<T>, o2: Option<T>) -> bool {
    return o1 == o2;
}

fn match_(ui: &UserID, vuid: &UserID) -> bool {
    vuid.email().unwrap_or(None) == ui.email().unwrap_or(None)
}

fn match_id<'a>(ui: UserID, certs: &Vec<Cert>) -> Option<&Cert> {
    for cert in certs.into_iter() {
        if cert.userids().any(|vuid| match_(&ui, vuid.component())) {
            return Some(cert)
        }
    }
    None
}

fn match_ids<'a>(ui: UserID, certs: &Vec<Cert>) -> Option<&Cert> {
    for cert in certs.into_iter() {
        if cert.userids().any(|vuid| match_(&ui, vuid.component())) {
            return Some(cert)
        }
    }
    None
}

fn find_cert<'a>(certs: &'a Vec<Cert>, uid: &'a str) -> Option<&'a Cert> {
    let uid = UserID::from(uid);

    if let Some(cert) = match_id(uid, &certs) {
        return Some(cert);
    }
    None
}

// Exports certs based on key-ids
pub fn export_keys(ctx: &SqContext, key_ids: &[&str], 
    output: &mut (dyn io::Write + Send + Sync))
    -> openpgp::Result<i32> {
    let userids = key_ids.iter().map(|key| UserID::from(*key));

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let mut message = Message::new(output);
    message = Armorer::new(message).kind(armor::Kind::PublicKey).build()?;

    let mut num = 0;
    for uid in userids.into_iter() {
        if let Some(cert) = match_id(uid, &certs) {
            cert.serialize(&mut message)?;
            num = num + 1;
        }
    }
    message.finalize()?;
    Ok(num)
}

// Import certs into the db and try to merge them with existing ones
pub fn import_keys(ctx: &SqContext, input: &mut (dyn io::Read + Send + Sync))
    -> openpgp::Result<i32> {

    let path = ctx.keyring.borrow();
    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();
    let mut output = File::open(&*path)?;
    for cert in CertParser::from_reader(input)? {
        let cert = cert.context(
            format!("Trying to import Malformed certificate into keyring"))?;
        match certs.entry(cert.fingerprint()) {
            e @ Entry::Vacant(_) => {
                e.or_insert(Some(cert));
            }
            Entry::Occupied(mut e) => {
                let e = e.get_mut();
                let curr = e.take().unwrap();
                *e = Some(curr.merge_public_and_secret(cert)
                    .expect("Same certificate"));
            }
        }
    }

    // don't write all keys, only write new keys
    let mut fingerprints: Vec<Fingerprint> = certs.keys().cloned().collect();
    fingerprints.sort();

    let mut num = 0;
    for fpr in fingerprints.iter() {
        if let Some(Some(cert)) = certs.get(fpr) {
            cert.serialize(&mut output)?;
        }
        num = num + 1;
    }
    Ok(num)
}

// fn get_keys<C>(certs: &[C], p: &dyn Policy,
//                private_key_store: Option<&str>,
//                timestamp: Option<SystemTime>,
//                keytype: KeyType,
//                options: Option<&[GetKeysOptions]>)
//     -> Result<Vec<Box<dyn crypto::Signer + Send + Sync>>>
//     where C: Borrow<Cert>
// // {
//     let mut bad = Vec::new();
//
//     let options = options.unwrap_or(&[][..]);
//     let allow_not_alive = options.contains(&GetKeysOptions::AllowNotAlive);
//     let allow_revoked = options.contains(&GetKeysOptions::AllowRevoked);
//
//     let mut keys: Vec<Box<dyn crypto::Signer + Send + Sync>> = Vec::new();
//     'next_cert: for tsk in certs {
//         let tsk = tsk.borrow();
//         let vc = match tsk.with_policy(p, timestamp) {
//             Ok(vc) => vc,
//             Err(err) => {
//                 return Err(
//                     err.context(format!("Found no suitable key on {}", tsk)));
//             }
//         };
//
//         let keyiter = match keytype {
//             KeyType::Primary => {
//                 Box::new(
//                     std::iter::once(
//                         vc.keys()
//                             .next()
//                             .expect("a valid cert has a primary key")))
//                     as Box<dyn Iterator<Item=ValidErasedKeyAmalgamation<openpgp::packet::key::PublicParts>>>
//             },
//             KeyType::KeyFlags(ref flags) => {
//                 Box::new(vc.keys().key_flags(flags.clone()))
//                     as Box<dyn Iterator<Item=_>>
//             },
//         };
//         for ka in keyiter {
//             let bad_ = [
//                 ! allow_not_alive && matches!(ka.alive(), Err(_)),
//                 ! allow_revoked && matches!(ka.revocation_status(),
//                                             RevocationStatus::Revoked(_)),
//                 ! ka.pk_algo().is_supported(),
//             ];
//             if bad_.iter().any(|x| *x) {
//                 bad.push((ka.fingerprint(), bad_));
//                 continue;
//             }
//
//             let key = ka.key();
//
//             if let Some(secret) = key.optional_secret() {
//                 let unencrypted = match secret {
//                     SecretKeyMaterial::Encrypted(ref e) => {
//                         let password = rpassword::prompt_password(
//                             &format!("Please enter password to decrypt {}/{}: ",
//                                      tsk, key))
//                             .context("Reading password from tty")?;
//                         e.decrypt(key.pk_algo(), &password.into())
//                             .expect("decryption failed")
//                     },
//                     SecretKeyMaterial::Unencrypted(ref u) => u.clone(),
//                 };
//
//                 keys.push(Box::new(crypto::KeyPair::new(key.clone(), unencrypted)
//                           .unwrap()));
//                 continue 'next_cert;
//             } else if let Some(private_key_store) = private_key_store {
//                 let password = rpassword::prompt_password(
//                     &format!("Please enter password to key {}/{}: ", tsk, key)).unwrap().into();
//                 match pks::unlock_signer(private_key_store, key.clone(), &password) {
//                     Ok(signer) => {
//                         keys.push(signer);
//                         continue 'next_cert;
//                     },
//                     Err(error) => eprintln!("Could not unlock key: {:?}", error),
//                 }
//             }
//         }
//
//         let timestamp = timestamp.map(|t| {
//             chrono::DateTime::<chrono::offset::Utc>::from(t)
//         });
//
//         let mut context = Vec::new();
//         for (fpr, [not_alive, revoked, not_supported]) in bad {
//             let id: String = if fpr == tsk.fingerprint() {
//                 fpr.to_string()
//             } else {
//                 format!("{}/{}", tsk.fingerprint(), fpr)
//             };
//
//             let preface = if let Some(t) = timestamp {
//                 format!("{} was not considered because\n\
//                          at the specified time ({}) it was",
//                         id, t)
//             } else {
//                 format!("{} was not considered because\nit is", fpr)
//             };
//
//             let mut reasons = Vec::new();
//             if not_alive {
//                 reasons.push("not alive");
//             }
//             if revoked {
//                 reasons.push("revoked");
//             }
//             if not_supported {
//                 reasons.push("not supported");
//             }
//
//             context.push(format!("{}: {}",
//                                  preface, reasons.join(", ")));
//         }
//
//         if context.is_empty() {
//             return Err(anyhow::anyhow!(
//                 format!("Found no suitable key on {}", tsk)));
//         } else {
//             let context = context.join("\n");
//             return Err(
//                 anyhow::anyhow!(
//                     format!("Found no suitable key on {}", tsk))
//                     .context(context));
//         }
//     }
//
//     Ok(keys)
// }

// They should return errors and not empty vec![]
fn get_keys_finger_prints<C>(certs: &[C], policy: &dyn Policy, ts: Option<SystemTime>, fp: Fingerprint) -> Vec<Key<PublicParts, UnspecifiedRole>>
    where C: Borrow<Cert> {
    for c in certs {
        let cert: &Cert = c.borrow();
        if cert.fingerprint() == fp {
            return cert.keys().with_policy(policy, ts).alive()
                .revoked(false).for_signing().map(|x| x.key().clone()).collect()
        }
    }
    vec![]
}

fn get_keys_uid<C>(certs: &[C], policy: &dyn Policy, ts: Option<SystemTime>, uid: UserID) -> Vec<Key<PublicParts, UnspecifiedRole>>
    where C: Borrow<Cert> {
    let mut keys = vec![];
    for c in certs {
        let cert: &Cert = c.borrow();
        if cert.userids().any(|vuid| match_(&uid, vuid.component())) {
            for ka in cert.keys().with_policy(policy, ts).alive().revoked(false).for_signing() {
                keys.push(ka.key().clone())
            }
        }
    }
    keys
}

fn find_keys<C>(certs: &[C], policy: &dyn Policy, ts: Option<SystemTime>, pattern: Option<&str>) -> Vec<Key<PublicParts, UnspecifiedRole>>
    where C: Borrow<Cert> {
    if let Some(pattern) = pattern {
        if let Ok(fingerprint) = Fingerprint::from_hex(pattern) {
            return get_keys_finger_prints(certs, policy, ts, fingerprint)
        } 
        let uid = UserID::from(pattern);
        return get_keys_uid(certs, policy, ts, uid)
    } else {
        let mut keys = vec![];
        for c in certs {
            let cert: &Cert = c.borrow();
            for ka in cert.keys().with_policy(policy, ts).alive().revoked(false).for_signing() {
                keys.push(ka.key().clone());
            }
        }
        return keys;
    }
}

fn get_signing_key<C>(certs: &[C], p: &dyn Policy,
               pattern: Option<&str>,
               timestamp: Option<SystemTime>)
    -> openpgp::Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: Borrow<Cert> {
    
    let keys = find_keys(certs, p, timestamp, pattern);
    keys[0].optional_secret();
//
//     for tsk in certs {
//         let tsk = tsk.borrow();
//         let keys = tsk.keys().unencrypted_secret()
//             .with_policy(p, timestamp).alive().revoked(false).for_signing()
//             .map(|x| x.unwrap().keys())
//         if key.is_ok() {
//             return key
//         }
//     }
//     for tsk in certs {
//         let tsk = tsk.borrow();
//         let key = tsk.keys().encryp()
//             .with_policy(p, timestamp).alive().revoked(false).for_signing()
//             .nth(0).unwrap().key().clone().into_keypair();
//         if key.is_ok() {
//             return key
//         }
//     }
//
//     return Err(anyhow::anyhow!("No keys found"))
// }
//

pub fn sign(ctx: &SqContext, policy: &dyn Policy, detach: bool,
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), userid: &str)
    -> openpgp::Result<i32> {

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let tsk = find_cert(&certs, userid);

    if tsk.is_none() {
        return Err(anyhow::anyhow!(
            "Can't find key for signing"))
    }
    let tsk = tsk.unwrap();

    if detach {
        sign_detach(policy,input, output, &tsk)
    } else {
        clearsign(policy, input, output, &tsk)
    }
}

fn find_key_pair<'a>(certs: &'a Vec<Cert>, policy: &dyn Policy, uid: &'a str) -> Option<KeyPair> {
    let tsk = find_cert(certs, uid)?;
    tsk .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair().ok()
}

fn clearsign(policy: &dyn Policy,
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), tsk: &openpgp::Cert)
    -> openpgp::Result<i32>
{
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;

    let message = Message::new(output);

    let signer = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Text))
        .cleartext();

    let mut message = signer.build()?;
    io::copy(input, &mut message)?;

    message.finalize()?;
 
    Ok(10)
}

fn sign_detach(policy: &dyn Policy,
        input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync), tsk: &openpgp::Cert)
    -> openpgp::Result<i32>
{
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;

    let message = Message::new(output);

    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Signature)
        .build()?;

    let mut message = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Binary))
        .detached().build()?;

    io::copy(input, &mut message)?;

    message.finalize()?;
 
    Ok(10)
}

// pub fn find_cert(userid: &str) -> openpgp::Result<openpgp::Cert> {
//     todo!()
// }

struct VHelper<'a> {
    ctx: &'a SqContext,
    
    trusted: HashSet<KeyID>,
    list: gmime::SignatureList,
}

pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

macro_rules! cert_set {
    ($cert:ident.$var:ident, $value:expr) => {
        match $value {
            Ok(v) => {
                match v {
                    Some(v) => $cert.$var(&v),
                    _ => {}
                }
            }
            _ => {}
        }
    };
}

fn algo_to_algo(algo: PublicKeyAlgorithm) -> PubKeyAlgo {
    // We assume that if we can encrypt with a key, we can sign with it.
    // The other way around isn't true
    match algo {
        PublicKeyAlgorithm::RSAEncryptSign => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::RSAEncrypt => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::RSASign => gmime::PubKeyAlgo::RsaS,
        PublicKeyAlgorithm::ElGamalEncrypt => gmime::PubKeyAlgo::ElgE,
        PublicKeyAlgorithm::DSA => gmime::PubKeyAlgo::Dsa,
        PublicKeyAlgorithm::ECDH => gmime::PubKeyAlgo::Ecdh,
        PublicKeyAlgorithm::ECDSA => gmime::PubKeyAlgo::Ecdsa,
        PublicKeyAlgorithm::ElGamalEncryptSign => gmime::PubKeyAlgo::ElgE,
        PublicKeyAlgorithm::EdDSA => gmime::PubKeyAlgo::RsaE,
        PublicKeyAlgorithm::Private(v) => gmime::PubKeyAlgo::__Unknown(v as i32),
        PublicKeyAlgorithm::Unknown(v) => gmime::PubKeyAlgo::__Unknown(v as i32),
        _ => todo!(),
    }
}

fn cypher_to_cypher(algo: SymmetricAlgorithm) -> gmime::CipherAlgo {
    match algo {
        // this shouldn't happen?
        SymmetricAlgorithm::Unencrypted => todo!(),
        SymmetricAlgorithm::IDEA => gmime::CipherAlgo::Idea,
        SymmetricAlgorithm::TripleDES => gmime::CipherAlgo::_3des,
        SymmetricAlgorithm::CAST5 => gmime::CipherAlgo::Cast5,
        SymmetricAlgorithm::Blowfish => gmime::CipherAlgo::Blowfish,
        SymmetricAlgorithm::AES128 => gmime::CipherAlgo::Aes,
        SymmetricAlgorithm::AES192 => gmime::CipherAlgo::Aes192,
        SymmetricAlgorithm::AES256 => gmime::CipherAlgo::Aes256,
        SymmetricAlgorithm::Twofish => gmime::CipherAlgo::Twofish,
        SymmetricAlgorithm::Camellia128 => gmime::CipherAlgo::Camellia128,
        SymmetricAlgorithm::Camellia192 => gmime::CipherAlgo::Camellia192,
        SymmetricAlgorithm::Camellia256 => gmime::CipherAlgo::Camellia256,
        SymmetricAlgorithm::Private(_) => todo!(),
        SymmetricAlgorithm::Unknown(_) => todo!(),
        _ => todo!(),
    }
}

fn hash_to_hash(algo: HashAlgorithm) -> DigestAlgo {
    match algo {
        HashAlgorithm::MD5 => gmime::DigestAlgo::Md5,
        HashAlgorithm::SHA1 => gmime::DigestAlgo::Sha1,
        HashAlgorithm::RipeMD => gmime::DigestAlgo::Ripemd160,
        HashAlgorithm::SHA256 => gmime::DigestAlgo::Sha256,
        HashAlgorithm::SHA384 => gmime::DigestAlgo::Sha384,
        HashAlgorithm::SHA512 => gmime::DigestAlgo::Sha512,
        HashAlgorithm::SHA224 => gmime::DigestAlgo::Sha224,
        HashAlgorithm::Private(v) => gmime::DigestAlgo::__Unknown(v as i32),
        HashAlgorithm::Unknown(v) => gmime::DigestAlgo::__Unknown(v as i32),
        _ => todo!(),
    }
}

macro_rules! unix_time {
    ($cert:ident.$var:ident, $value:expr) => {
        match $value {
            Some(v) => {
                match v.duration_since(SystemTime::UNIX_EPOCH) {
                    Ok(v) => $cert.$var(v.as_secs() as i64),
                    _ => {}
                }
            }
            _ => {}
        }
    };
}

impl<'a> VHelper<'a> {
    fn new(ctx: &'a SqContext)
           -> Self {
        let list = gmime::SignatureList::new();
        VHelper {
            ctx,
            trusted: HashSet::new(),
            list,
        }
    }

    fn make_signature(&self, sig: &Signature, status: gmime::SignatureStatus,
        key: Option<&ValidErasedKeyAmalgamation<'a, key::PublicParts>>)
        -> gmime::Signature {
            let gsig = gmime::Signature::new();

            gsig.set_status(status);
            unix_time!(gsig.set_expires, sig.signature_expiration_time());
            unix_time!(gsig.set_created, sig.signature_creation_time());

            let cert = gmime::Certificate::new();
            cert.set_pubkey_algo(algo_to_algo(sig.pk_algo()));
            cert.set_digest_algo(hash_to_hash(sig.hash_algo()));
            let finger = sig.issuer_fingerprints().next();
            if let Some(finger) = finger {
                let finger = finger.to_hex();
                cert.set_fingerprint(&finger);
                cert.set_key_id(&finger);
            }

            if let Some(key) = key {
                let issuer = key.key().keyid();
                let level = sig.level();

                let trusted = self.trusted.contains(&issuer);

                // TODO: Are these trust leveles mapped correctly?
                let trust = match (trusted, level) {
                    (true, 0) => gmime::Trust::Full,
                    (true, 1) => gmime::Trust::Marginal,
                    (false, _) => gmime::Trust::Unknown,
                    (_, _) => gmime::Trust::Unknown,
                };
                if let Ok(id) = key.cert().primary_userid() {
                    cert.set_trust(trust);
                    cert_set!(cert.set_name, id.name());
                    cert_set!(cert.set_email, id.email());

                    let userid = String::from_utf8_lossy(&id.userid().value()[..]);

                    cert.set_user_id(&userid);
                }

                // TODO:
                // if we find subkeys, just set the date of the subkeys instead

                // cert.set_created();
                // cert.set_expires();
            } else {
                cert.set_trust(gmime::Trust::Never)
            }
            gsig.set_certificate(&cert);

            gsig
    }

    fn to_siglist(&mut self, result: &[VerificationResult])
        -> Result<()> {
        for (idx, res) in result.iter().enumerate() {
            match res {
                Ok(ref res) => {
                    let sig = self.make_signature(res.sig, gmime::SignatureStatus::Green, Some(&res.ka));
                    self.list.insert(idx as i32, &sig);
                }
                Err(ref err) => {
                    // XXX: These errors are not matched correctly
                    match err {
                        openpgp::parse::stream::VerificationError::MalformedSignature { sig, error } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::SysError, None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::MissingKey { sig } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::KeyMissing, None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::UnboundKey { sig, cert, error } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red, None);
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::BadKey { sig, ka, error } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red, 
                                Some(ka));
                            self.list.add(&sig);
                        }
                        openpgp::parse::stream::VerificationError::BadSignature { sig, ka, error } => {
                            let sig = self.make_signature(sig, gmime::SignatureStatus::Red,
                                Some(ka));
                            self.list.add(&sig);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        // let certs = self.certs.take().unwrap();

        let path = self.ctx.keyring.borrow();
        let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();
        //
        // Explicitly provided keys are trusted.
        self.trusted = seen;


        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    self.to_siglist(results)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// TODO: Handle flags
pub fn verify(ctx: &SqContext, policy: &dyn Policy, flags: gmime::VerifyFlags, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<Option<gmime::SignatureList>> {

    let helper = VHelper::new(&ctx);
    let helper = if let Some(dsig) = sigstream {
        let mut v = DetachedVerifierBuilder::from_reader(dsig)?
            .with_policy(policy, None, helper)?;
        v.verify_reader(input)?;
        v.into_helper()
    } else {
        let mut v = VerifierBuilder::from_reader(input)?
            .with_policy(policy, None, helper)?;
        if let Some(output) = output {
            io::copy(&mut v, output)?;
            v.into_helper()
        } else {
            return Err(anyhow::anyhow!("None detach message but no output stream"))
        }
    };

    Ok(Some(helper.list))
}

struct DHelper<'a> {
    ctx: &'a SqContext,
    sk: Option<SessionKey>,
    flags: DecryptFlags,

    helper: VHelper<'a>,

    // secret_keys: HashMap<KeyID, Box<dyn PrivateKey>>,
    key_identities: HashMap<KeyID, Fingerprint>,
    // certs: HashMap<KeyID, ValidCert<'a>>,
    // keys: HashMap<KeyID, KeyPair>,
    keys: HashMap<KeyID, (Fingerprint, KeyPair)>,
    key_hints: HashMap<KeyID, String>,
    
    result: gmime::DecryptResult,
}

impl<'a> DHelper<'a> {
    fn new(ctx: &'a SqContext, policy: &dyn Policy, flags: DecryptFlags, secrets: Vec<Cert>, sk: Option<SessionKey>)
           -> Self {
        // let mut keys: HashMap<KeyID, Box<dyn PrivateKey>> = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        // let mut certs: HashMap<KeyID, Cert> = HashMap::new();
        // let mut certs: HashMap<KeyID, KeyPair> = HashMap::new();
        let mut keys: HashMap<KeyID, (Fingerprint, KeyPair)> = HashMap::new();

        let result = gmime::DecryptResult::new();

        for cert in secrets {
            let hint = match cert.with_policy(policy, None)
                .and_then(|valid_cert| valid_cert.primary_userid()).ok()
            {
                Some(uid) => format!("{} ({})", uid.userid(),
                                     KeyID::from(cert.fingerprint())),
                None => format!("{}", KeyID::from(cert.fingerprint())),
            };

            for ka in cert.keys()
                .unencrypted_secret()
                .with_policy(policy, None)
                .supported()
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().keyid();
                identities.insert(id.clone(), cert.fingerprint());
                keys.insert(id.clone(), (cert.fingerprint(), ka.key().clone().into_keypair().unwrap()));
                hints.insert(id, hint.clone());
            }
        }

        DHelper {
            ctx,
            sk,
            flags,

            helper: VHelper::new(ctx),

            keys,
            key_hints: hints,
            key_identities: identities,

            result,
        }
    }

}

#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: openpgp::crypto::SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl<'a> VerificationHelper for DHelper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.helper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        let certresult_list = gmime::CertificateList::new();
        self.result.set_recipients(&certresult_list);

        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    self.helper.to_siglist(results)?;
                }
                MessageLayer::Compression { algo } => {
                }
                MessageLayer::Encryption { sym_algo, aead_algo } => {
                    let cert = gmime::Certificate::new();
                    // TODO: set the pubkey algorithm
                    // cert.set_pubkey_algo(cypher_to_cypher(sym_algo));
                    // cert.set_key_id(key_id)
                    certresult_list.add(&cert);
                }
            }
        }
        Ok(())
    }
}

// macro_rules! bit {
//     ($flag:expr, $name:expr) => {
//         ($flags & $name.bits()) > 0
//     };
// }
// if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D)
        -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool
    {

        if let Some(sk) = &self.sk {
            let decrypted = if let Some(sa) = sk.symmetric_algo {
                let res = decrypt(sa, &sk.session_key);
                if res {
                    self.result.set_cipher(cypher_to_cypher(sa));
                }
                res
            } else {
                // We don't know which algorithm to use,
                // try to find one that decrypts the message.
                let mut ret = false;

                for i in 1u8..=19 {
                    let sa = SymmetricAlgorithm::from(i);
                    if decrypt(sa, &sk.session_key) {
                        self.result.set_cipher(cypher_to_cypher(sa));
                        ret = true;
                        break;
                    }
                }
                ret
            };
            if decrypted {
                if (self.flags & gmime::DecryptFlags::EXPORT_SESSION_KEY).bits() > 0 {
                    self.result.set_session_key(Some(&hex::encode(&sk.session_key)));
                }
                return Ok(None);
            }
        }

        for pkesk in pkesks {
            if let Some((fp, pair)) = self.keys.get_mut(pkesk.recipient()) {
                if pkesk.decrypt(pair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                        .unwrap_or(false)
                {
                    return Ok(Some(fp.clone()))
                }
            }
        }

        Ok(None)


        // 'next_key: for pkesk in pkesks {
        //     // Don't ask the user to decrypt a key if we don't support
        //     // the algorithm.
        //     if ! pkesk.pk_algo().is_supported() {
        //         continue;
        //     }
        //
        //     let keyid = pkesk.recipient();
        //     // let stream = gmime::StreamMem::new();
        //     if let Some(key) = self.secret_keys.get_mut(keyid) {
        //         let mut retry = 0;
        //         let keypair = loop {
        //             if retry > 3 {
        //                 continue 'next_key;
        //             }
        //             if let Some(keypair) = key.get_unlocked() {
        //                 break keypair;
        //             }
        //
        //             let uid = self.key_hints.get(keyid).unwrap();
        //             let p = self.sq.ask_password(uid,
        //                 "Enter password to decrypt key", retry != 0
        //             )?.into();
        //             
        //             retry = retry + 1;
        //
        //             match key.unlock(&p) {
        //                 Ok(decryptor) => break decryptor,
        //                 Err(error) => {
        //                     // eprintln!("Could not unlock key: {:?}", error),
        //                 }
        //             }
        //         };
        //
        //         if let Some(fp) =
        //             self.try_decrypt(pkesk, sym_algo, keypair,
        //                              &mut decrypt)
        //         {
        //             return Ok(fp);
        //         }
        //     }
        // }
        //
        // for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
        //     for key in self.secret_keys.values() {
        //         if let Some(fp) = key.get_unlocked()
        //             .and_then(|k|
        //                       self.try_decrypt(pkesk, sym_algo, k, &mut decrypt))
        //         {
        //             return Ok(fp);
        //         }
        //     }
        // }
        //
        // for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
        //     // Don't ask the user to decrypt a key if we don't support
        //     // the algorithm.
        //     if ! pkesk.pk_algo().is_supported() {
        //         continue;
        //     }
        //
        //     // To appease the borrow checker, iterate over the
        //     // hashmap, awkwardly.
        //     for keyid in self.secret_keys.keys().cloned().collect::<Vec<_>>()
        //     {
        //         let keypair = loop {
        //             let key = self.secret_keys.get_mut(&keyid).unwrap(); // Yuck
        //
        //             if let Some(keypair) = key.get_unlocked() {
        //                 break keypair;
        //             }
        //
        //             // XXX: Make the password loop breakable
        //             let uid = self.key_hints.get(&keyid).unwrap();
        //             let p = self.sq.ask_password(self, uid,
        //                 "Enter password to decrypt key", 0 != 0
        //             )?.into();
        //
        //             if let Ok(decryptor) = key.unlock(&p) {
        //                 break decryptor;
        //             } else {
        //                 eprintln!("Bad password.");
        //             }
        //         };
        //
        //         if let Some(fp) =
        //             self.try_decrypt(pkesk, sym_algo, keypair,
        //                              &mut decrypt)
        //         {
        //             return Ok(fp);
        //         }
        //     }
        // }

        // if skesks.is_empty() {
        //     return
        //         Err(anyhow::anyhow!("No key to decrypt message"));
        // }
        //
        // // Finally, try to decrypt using the SKESKs.
        // loop {
        //     // XXX: Make the password loop breakable
        //     // let uid = self.key_hints.get(keyid).unwrap();
        //     let p = sq::prompt_password(self, uid,
        //         "Enter password to decrypt key", retry != 0
        //     )?.into();
        //
        //     for skesk in skesks {
        //         if let Some(sk) = skesk.decrypt(&password).ok()
        //             .and_then(|(algo, sk)| { if decrypt(algo, &sk) { Some(sk) } else { None }})
        //         {
        //             if self.dump_session_key {
        //                 eprintln!("Session key: {}", hex::encode(&sk));
        //             }
        //             return Ok(None);
        //         }
        //     }
        // }
    }
}

// TODO: Handle more flags
pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<gmime::DecryptResult> {

    let sk = sk.map(|x| SessionKey::from_str(x).ok()).flatten();
    let path = ctx.keyring.borrow();
    let secrets: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let helper = DHelper::new(&ctx, policy, flags, secrets, sk);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        .with_policy(policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output)?;

    let helper = decryptor.into_helper();
    helper.result.set_signatures(&helper.helper.list);
    Ok(helper.result)
}

// TODO: Handle more flags
pub fn encrypt(ctx: &SqContext, policy: &dyn Policy, flags: EncryptFlags,
    sign: bool, userid: Option<&str>, recipients: &[&str],
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync))
        -> Result<i32> {

    if recipients.len() == 0 {
        return Err(anyhow::anyhow!(
            "Not recipient"));
    }

    let mode = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    let mut signing_keys: Vec<&Cert> = Vec::new();

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();

    for uid in recipients.iter().map(|key| UserID::from(*key)) {
        if let Some(cert) = match_id(uid, &certs) {
        for key in cert.keys().with_policy(policy, None).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key()) {
                recipient_subkeys.push(key.into());
                signing_keys.push(cert);
            }
        } else {
            return Err(anyhow::anyhow!(
                    "Can't find all recipients"));
        }
    }

    let message = Message::new(output);

    let message = Armorer::new(message).build()?;
    let encryptor = Encryptor::for_recipients(message, recipient_subkeys);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    if flags != EncryptFlags::NoCompress {
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?;
    }

    if sign {
        if let Some(userid) = userid {
            if let Some(cert) = find_key_pair(&certs, policy, userid) {
                let mut signer = Signer::new(sink, cert);
                for r in signing_keys.iter() {
                    signer = signer.add_intended_recipient(r);
                }
                sink = signer.build()?;
            } else {
                return Err(anyhow::anyhow!("Couldn't find signing cert for: {}", userid));
            }
        } else {
            return Err(anyhow::anyhow!("Signing enabled but no id"));
        }
    }

    let mut literal_writer = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(0)
}
