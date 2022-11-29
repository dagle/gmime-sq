use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::File, io::{self, Read, Write}, time::SystemTime};
 
extern crate sequoia_openpgp as openpgp;
use gmime::{traits::{SignatureListExt, SignatureExt, CertificateExt}, PubKeyAlgo, DigestAlgo, DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, armor, types::{SignatureType, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, SymmetricAlgorithm}, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder, VerificationResult, DecryptorBuilder, DecryptionHelper}, KeyID, cert::{prelude::ValidErasedKeyAmalgamation, amalgamation::ValidAmalgamation}, crypto::{SessionKey, self}};
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

// Exports certs based on key-ids
pub fn export_keys(ctx: &SqContext, key_ids: &[&str], 
    output: &mut (dyn io::Write + Send + Sync))
    -> openpgp::Result<i32> {
    let userids = key_ids.iter().map(|key| UserID::from(*key));

    // TODO don't use filter_map
    let path = ctx.keyring.borrow();
    let certs: Vec<Cert> = CertParser::from_file(&*path)?.filter_map(|cert| cert.ok()).collect();
    let mut message = Message::new(output);
    message = Armorer::new(message).kind(armor::Kind::PublicKey).build()?;

    let mut num = 0;
    for uid in userids.into_iter() {
        if let Some(cert) = match_id(uid, &certs) {
            cert.serialize(&mut message)?;
            num = num + 1;
        } else {
            // TODO should we do this or should we just skip and return
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

pub fn sign(policy: &dyn Policy, detach: bool,
        output: impl Write + Send + Sync, input: impl Read + Send + Sync, tsk: &openpgp::Cert)
    -> openpgp::Result<i32> {
    if detach {
        sign_detach(policy, output, input, tsk)
    } else {
        clearsign(policy, output, input, tsk)
    }
}

fn clearsign(policy: &dyn Policy,
        mut output: impl Write + Send + Sync, mut input: impl Read + Send + Sync, tsk: &openpgp::Cert)
    -> openpgp::Result<i32>
{
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;
 
    // Start streaming an OpenPGP message.
    let message = Message::new(&mut output);
 
    // We want to sign a literal data packet.
    let mut message = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Text))
        .cleartext().build()?;
 
    // Sign the data.
    io::copy(&mut input, &mut message)?;
 
    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;
 
    Ok(0)
}

fn sign_detach(policy: &dyn Policy,
        mut output: impl Write + Send + Sync, mut input: impl Read + Send + Sync, tsk: &openpgp::Cert)
    -> openpgp::Result<i32>
{
    // Get the keypair to do the signing from the Cert.
    let keypair = tsk
        .keys().unencrypted_secret()
        .with_policy(policy, None).alive().revoked(false).for_signing()
        .nth(0).unwrap().key().clone().into_keypair()?;
 
    // Start streaming an OpenPGP message.
    let mut message = Message::new(&mut output);
    message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
 
    // We want to sign a literal data packet.
    let mut message = Signer::with_template(
        message, keypair,
        signature::SignatureBuilder::new(SignatureType::Text))
        .detached().build()?;
 
    // Sign the data.
    io::copy(&mut input, &mut message)?;
 
    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize()?;
 
    Ok(0)
}

pub fn find_cert(userid: &str) -> openpgp::Result<openpgp::Cert> {
    todo!()
}

struct Helper<'a> {
    ctx: &'a SqContext,
    
    certs: Option<Vec<Cert>>,

    labels: HashMap<KeyID, String>,
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

fn make_signature<'a>(sig: &Signature, status: gmime::SignatureStatus,
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
            if let Ok(id) = key.cert().primary_userid() {
                cert.set_trust(gmime::Trust::Full);
                cert_set!(cert.set_name, id.name());
                cert_set!(cert.set_email, id.email());

                let userid = String::from_utf8_lossy(&id.userid().value()[..]);
                
                cert.set_user_id(&userid);
            }

            // XXX: TODO

            // if we find subkeys, just set the date of the subkeys instead
            // cert.set_created();
            // cert.set_expires();
        } else {
            cert.set_trust(gmime::Trust::Undefined)
        }
        gsig.set_certificate(&cert);

        gsig
}

impl<'a> Helper<'a> {
    fn new(ctx: &'a SqContext)
           -> Self {
        let list = gmime::SignatureList::new();
        Helper {
            // config: config.clone(),
            ctx,
            // TODO read cert from ctx.path
            certs: None,
            labels: HashMap::new(),
            trusted: HashSet::new(),
            list,
        }
    }
    fn to_siglist(&mut self, result: &Vec<VerificationResult>)
        -> Result<()> {
        for (idx, res) in result.iter().enumerate() {
            match res {
                Ok(ref res) => {
                    let sig = make_signature(res.sig, gmime::SignatureStatus::Green, Some(&res.ka));
                    self.list.insert(idx as i32, &sig);
                }
                Err(ref err) => {
                    // XXX: These errors are not matched correctly
                    match err {
                        openpgp::parse::stream::VerificationError::MalformedSignature { sig, error } => {
                            let sig = make_signature(sig, gmime::SignatureStatus::SysError, None);
                            self.list.insert(idx as i32, &sig);
                        }
                        openpgp::parse::stream::VerificationError::MissingKey { sig } => {
                            let sig = make_signature(sig, gmime::SignatureStatus::KeyMissing, None);
                            self.list.insert(idx as i32, &sig);
                        }
                        openpgp::parse::stream::VerificationError::UnboundKey { sig, cert, error } => {
                            let sig = make_signature(sig, gmime::SignatureStatus::Red, None);
                            self.list.insert(idx as i32, &sig);
                        }
                        openpgp::parse::stream::VerificationError::BadKey { sig, ka, error } => {
                            let sig = make_signature(sig, gmime::SignatureStatus::Red, 
                                Some(ka));
                            self.list.insert(idx as i32, &sig);
                        }
                        openpgp::parse::stream::VerificationError::BadSignature { sig, ka, error } => {
                            let sig = make_signature(sig, gmime::SignatureStatus::Red,
                                Some(ka));
                            self.list.insert(idx as i32, &sig);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<'a> VerificationHelper for Helper<'a> {
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
                // TODO all we want to do is just return results, gmime-it and return
                // convert results to a Vec<GmimeSig>
                _ => return Err(anyhow::anyhow!(
                        "Only signature messages supported"))
            }
        }
        Ok(())
    }
}

/// Verifies a multipart_message (using detach) or a clear signed message
/// sigstream being None = signature is a part of input
/// ouput being None, we don't need to produce output because we have the clear text in input
pub fn verify(ctx: &SqContext, policy: &dyn Policy, flags: gmime::VerifyFlags, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<Option<gmime::SignatureList>> {

    // load certs
 
    let helper = Helper::new(&ctx);
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
    
    certs: Option<Vec<Cert>>,

    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    // list: gmime::SignatureList,
}

impl<'a> DHelper<'a> {
    fn new(ctx: &'a SqContext)
           -> Self {
        DHelper {
            // config: config.clone(),
            ctx,
            // TODO read cert from ctx.path
            certs: None,
            labels: HashMap::new(),
            trusted: HashSet::new(),
        }
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D)
        -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        // The encryption key is the first and only subkey.
        // TODO: We need to find the key in the keyring
        //
        // let key = self.secret.keys().unencrypted_secret()
        //     .with_policy(self.policy, None)
        //     .for_transport_encryption().nth(0).unwrap().key().clone();
        //
        // // The secret key is not encrypted.
        // let mut pair = key.into_keypair().unwrap();
        //
        // pkesks[0].decrypt(&mut pair, sym_algo)
        //     .map(|(algo, session_key)| decrypt(algo, &session_key));
        //
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<gmime::DecryptResult> {

    // let helper = DHelper::new(&ctx);
    // let mut decryptor = DecryptorBuilder::from_reader(input)?
    //     // .mapping(hex)
    //     .with_policy(&policy, None, helper)
    //     .context("Decryption failed")?;
    //
    // io::copy(&mut decryptor, output).context("Decryption failed")?;
    //
    // let helper = decryptor.into_helper();
    // if let Some(dumper) = helper.dumper.as_ref() {
    //     dumper.flush(&mut io::stderr())?;
    // }
    // helper.vhelper.print_status();
    Ok(gmime::DecryptResult::new())
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
    // for id in recipients.iter() {
    //     let mut count = 0;
    //     let cert = get_cert(id);
    //     for key in cert.keys().with_policy(policy, None).alive().revoked(false)
    //         .key_flags(&mode).supported().map(|ka| ka.key())
    //     {
    //         recipient_subkeys.push(key.into());
    //         count += 1;
    //     }
    // }

    let message = Message::new(output);
    let encryptor = Encryptor::for_recipients(message, recipient_subkeys);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    if flags != EncryptFlags::NoCompress {
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?;
    }

    // if sign {
    //     // let userid = userid.unwrap_or_else
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
