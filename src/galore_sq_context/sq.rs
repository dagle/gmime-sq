use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::File, io::{self, Read, Write}, time::SystemTime, str::FromStr, hash::Hash, ptr::hash};
 
extern crate sequoia_openpgp as openpgp;
use glib::Cast;
use gmime::{traits::{SignatureListExt, SignatureExt, CertificateExt, DecryptResultExt, CertificateListExt}, PubKeyAlgo, DigestAlgo, DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, armor, types::{SignatureType, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, SymmetricAlgorithm}, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder, VerificationResult, DecryptorBuilder, DecryptionHelper}, KeyID, cert::{prelude::ValidErasedKeyAmalgamation, amalgamation::ValidAmalgamation, ValidCert}, crypto::{self}, fmt::hex};
use openpgp::serialize::stream::*;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::Serialize;
use anyhow::Context;

// TODO should import and export have policies?
// TODO when to use String vs &str

use openpgp::{cert::{
        Cert,
        CertParser,
    }, packet::UserID};

use openpgp::parse::Parse;

use super::imp::SqContext;

struct GMimeCryptoContext {
    path: String,
}

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
        // } else {
            // TODO: should we do this or should we just skip and return
            // a number with all keys we exported?
            // return Err(anyhow::anyhow!("No keys were found"));
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

pub fn sign(ctx: &SqContext, policy: &dyn Policy, detach: bool,
        output: &mut (dyn Write + Send + Sync), input: &mut (dyn Read + Send + Sync), userid: &str)
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
        sign_detach(policy, output, input, &tsk)
    } else {
        clearsign(policy, output, input, &tsk)
    }
}

fn clearsign(policy: &dyn Policy,
        output: &mut (dyn Write + Send + Sync), input: &mut (dyn Read + Send + Sync), tsk: &openpgp::Cert)
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
        output: &mut (dyn Write + Send + Sync), input: &mut (dyn Read + Send + Sync), tsk: &openpgp::Cert)
    -> openpgp::Result<i32>
{
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;

    let message = Message::new(output);

    let mut message = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Text))
        .detached().cleartext().build()?;

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
                cert.set_trust(gmime::Trust::Undefined)
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
                // This shouldn't really happen
                _ => return Err(anyhow::anyhow!(
                        "Only signature messages supported"))
            }
        }
        Ok(())
    }
}

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

// trait PrivateKey {
//     fn get_unlocked(&self) -> Option<Box<dyn Decryptor>>;
//
//     fn unlock(&mut self, p: &Password) -> Result<Box<dyn Decryptor>>;
// }

struct DHelper<'a> {
    ctx: &'a SqContext,
    sk: Option<SessionKey>,

    helper: VHelper<'a>,

    // secret_keys: HashMap<KeyID, Box<dyn PrivateKey>>,
    key_identities: HashMap<KeyID, Fingerprint>,
    certs: HashMap<KeyID, ValidCert<'a>>,
    key_hints: HashMap<KeyID, String>,
    
    result: gmime::DecryptResult,
}

fn load_certs(file: &str) -> openpgp::Result<Vec<Cert>>
{
    let mut certs = vec![];
    for maybe_cert in CertParser::from_file(file)
        .context(format!("Failed to load certs from file {:?}", file))?
        {
            certs.push(maybe_cert.context(
                    format!("A cert from file {:?} is bad", file)
            )?);
        }
    Ok(certs)
}

impl<'a> DHelper<'a> {
    fn new(ctx: &'a SqContext, policy: &dyn Policy, secrets: Vec<Cert>, sk: Option<SessionKey>)
           -> Self {
        // let mut keys: HashMap<KeyID, Box<dyn PrivateKey>> = HashMap::new();
        let mut identities: HashMap<KeyID, Fingerprint> = HashMap::new();
        let mut hints: HashMap<KeyID, String> = HashMap::new();
        let mut certs: HashMap<KeyID, ValidCert<'a>> = HashMap::new();

        for tsk in secrets {
            let hint = match tsk.with_policy(policy, None)
                .and_then(|valid_cert| valid_cert.primary_userid()).ok()
            {
                Some(uid) => format!("{} ({})", uid.userid(),
                                     KeyID::from(tsk.fingerprint())),
                None => format!("{}", KeyID::from(tsk.fingerprint())),
            };

            for ka in tsk.keys()
            // XXX: Should use the message's creation time that we do not know.
                .with_policy(policy, None)
                .for_transport_encryption().for_storage_encryption()
            {
                let id: KeyID = ka.key().fingerprint().into();
                let key = ka.key();
                // keys.insert(id.clone(),
                //     if let Ok(key) = key.parts_as_secret() {
                //         Box::new(LocalPrivateKey::new(key.clone()))
                //     } else if let Some(store) = private_key_store {
                //         Box::new(RemotePrivateKey::new(key.clone(), store.to_string()))
                //     } else {
                //         panic!("Cert does not contain secret keys and private-key-store option has not been set.");
                //     }
                // );
                identities.insert(id.clone(), tsk.fingerprint());
                // certs.insert(id, tsk.va);
                hints.insert(id, hint.clone());
            }
        }

        DHelper {
            ctx,
            sk,

            helper: VHelper::new(ctx),

            // secret_keys: keys,
            certs,
            key_hints: hints,
            key_identities: identities,

            result: gmime::DecryptResult::new()
        }
    }

    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      sym_algo: Option<SymmetricAlgorithm>,
                      mut keypair: Box<dyn crypto::Decryptor>,
                      decrypt: &mut D)
                      -> Option<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &crypto::SessionKey) -> bool
    {
        let keyid = keypair.public().fingerprint().into();
        match pkesk.decrypt(&mut *keypair, sym_algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some((algo, sk)) } else { None }
            })
        {
            Some((sa, sk)) => {
                // TODO:
                // mdc (we don't do mdc?)
                self.result.set_session_key(Some(hex::encode(&sk).as_ref()));
                self.result.set_cipher(cypher_to_cypher(sa));

                let gcertlist = gmime::CertificateList::new();
                if let Some(cert) = self.certs.get(&keyid) {
                    // for k in cert.keys() {
                    // }
                    for id in cert.userids() {
                        // TODO:
                        // tust, issuer_serial, issuer_name, user_id, validity
                        // created, expires
                        let gcert = gmime::Certificate::new();

                        let fpr = self.key_identities.get(&keyid).map(|x| x.to_hex());

                        cert_set!(gcert.set_name, id.name());
                        cert_set!(gcert.set_email, id.email());
                        if let Some(fpr) = fpr {
                            gcert.set_fingerprint(&fpr);
                            gcert.set_key_id(&fpr);
                        }

                        let userid = String::from_utf8_lossy(&id.userid().value()[..]);

                        gcert.set_user_id(&userid);

                        // TODO: Set the correct trust value
                        gcert.set_trust(gmime::Trust::Full);

                        gcertlist.add(&gcert);
                    }
                }
                self.result.set_recipients(&gcertlist);

                Some(self.key_identities.get(&keyid).cloned())
            },
            None => None,
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

// impl SessionKey {
//     /// Returns an object that implements Display for explicitly opting into
//     /// printing a `SessionKey`.
//     pub fn display_sensitive(&self) -> SessionKeyDisplay {
//         SessionKeyDisplay { csk: self }
//     }
// }
//
// pub struct SessionKeyDisplay<'a> {
//     csk: &'a SessionKey,
// }
//
// /// Print the session key without prefix in hexadecimal representation.
// impl<'a> std::fmt::Display for SessionKeyDisplay<'a> {
//     fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//         let sk = self.csk;
//         write!(f, "{}", hex::encode(&sk.session_key))
//     }
// }

impl<'a> VerificationHelper for DHelper<'a> {
    fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        self.helper.get_certs(ids)
    }
    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        self.helper.check(structure)?;
        Ok(())
    }
}

impl<'a> DecryptionHelper for DHelper<'a> {
    fn decrypt<D>(&mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D)
        -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &openpgp::crypto::SessionKey) -> bool
    {

        // for sk in self.sk {
        // helper.result.set_signatures(&helper.helper.list);
        // let sk = self.sk.map(|x| SessionKey::from_str(x).ok()).flatten();
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
                self.result.set_session_key(Some(&hex::encode(&sk.session_key)));
                // eprintln!("Encrypted with Session Key {}", &sk.display_sensitive());
                return Ok(None);
            }
        }
        Ok(None)

        // for pkesk in pkesks {
        //     let keyid = pkesk.recipient();
        //     if let Some(key) = self.secret_keys.get_mut(keyid) {
        //         if let Some(fp) = key.get_unlocked()
        //             .and_then(|k|
        //                       self.try_decrypt(pkesk, sym_algo, k, &mut decrypt))
        //         {
        //             return Ok(fp);
        //         }
        //     }
        // }

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

pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<gmime::DecryptResult> {

    let sk = sk.map(|x| SessionKey::from_str(x).ok()).flatten();
    let path = ctx.keyring.borrow();
    let secrets = load_certs(&path)?;
    let helper = DHelper::new(&ctx, policy, secrets, sk);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        // .mapping(hex)
        .with_policy(policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    // if let Some(dumper) = helper.dumper.as_ref() {
    //     dumper.flush(&mut io::stderr())?;
    // }
    // helper.helper.print_status();
    helper.result.set_signatures(&helper.helper.list);
    Ok(helper.result)
}

fn get_primary_keys<C>(certs: &[C], p: &dyn Policy,
                       private_key_store: Option<&str>,)
                       // timestamp: Option<SystemTime>,
                       // options: Option<&[GetKeysOptions]>)
    -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
{
    todo!()
    // get_keys(certs, p, private_key_store, timestamp,
    //          KeyType::Primary, options)
}
fn get_cert(id: &&str) -> Cert {
    todo!()
}


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

    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();

    for uid in recipients.iter().map(|key| UserID::from(*key)) {
        if let Some(cert) = match_id(uid, &certs) {
        for key in cert.keys().with_policy(policy, None).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key()) {
                recipient_subkeys.push(key.into());
            }
        } else {
            return Err(anyhow::anyhow!(
                    "Can't find all recipients"));
        }
    }

    let message = Message::new(output);
    let encryptor = Encryptor::for_recipients(message, recipient_subkeys);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    if flags != EncryptFlags::NoCompress {
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?;
    }

    // if sign {
    //     if let Some(userid) = userid {
    //         let mut signers = get_signing_key()?;
    //         // &opts.signers, opts.policy, opts.private_key_store, opts.time, None)?;
    //         let mut signer = Signer::new(sink, signers);
    //     }
    //     for r in recipients.iter() {
    //         signer = signer.add_intended_recipient(r);
    //     }
    //     sink = signer.build()?;
    // }

    let mut literal_writer = LiteralWriter::new(sink).build()
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    literal_writer.finalize()
        .context("Failed to encrypt")?;

    Ok(0)
}
