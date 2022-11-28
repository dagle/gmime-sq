use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::File, io::{self, Read, Write}};
 
extern crate sequoia_openpgp as openpgp;
use gmime::{DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, KeyID, armor, parse::stream::{DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper, VerifierBuilder}, types::{CompressionAlgorithm, KeyFlags, SignatureType}, crypto};
use openpgp::serialize::stream::*;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy as P;
use openpgp::serialize::stream::Message;
// use openpgp::{cert::CertBuilder, crypto::Signer, serialize::Serialize};
use openpgp::{cert::CertBuilder, serialize::Serialize};
// use std::{collections::{HashMap, hash_map::Entry}, fmt::Write, fs::File, io::{self, Read}};
// // use openpgp::serialize::stream::{Message, Armorer};
use anyhow::Context;
//
// use openpgp::packet::prelude::*;
// use openpgp::serialize::stream::*;
// use openpgp::policy::StandardPolicy as P;

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

// static GMimeSignatureList *gpg_verify (GMimeCryptoContext *ctx, GMimeVerifyFlags flags,
// 				       GMimeStream *istream, GMimeStream *sigstream,
// 				       GMimeStream *ostream, GError **err);

// ctx is path, password function, etc
// flags are verifcation helper and/or policy?
// istream and sigstream is signed_message? how do we split these?
// ostream is sink is ?
// err is result

struct VHelper<'a> {
    ctx: &'a SqContext,
    
    // idk, number of signatures needing to pass
    // maybe not do this an pass that up to gmime
    // signatures: usize,
    certs: Option<Vec<Cert>>,

    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    result: gmime::SignatureList,
    // We need these to construct a 
    // GMimeSignatureList * list as output
    // good_signatures: usize,
    // good_checksums: usize,
    // unknown_checksums: usize,
    // bad_signatures: usize,
    // bad_checksums: usize,
    // broken_signatures: usize,
}

impl<'a> VHelper<'a> {
    fn new(ctx: &'a SqContext)
           -> Self {
        let list = gmime::SignatureList::new();
        VHelper {
            // config: config.clone(),
            ctx,
            // TODO read cert from ctx.path
            certs: None,
            labels: HashMap::new(),
            trusted: HashSet::new(),
            result: list,
        }
    }
}

pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        let certs = self.certs.take().unwrap();
        // Get all keys.
        let seen: HashSet<_> = certs.iter()
            .flat_map(|cert| {
                cert.keys().map(|ka| ka.key().fingerprint().into())
            }).collect();

        // Explicitly provided keys are trusted.
        self.trusted = seen;

        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> Result<()> {
        for layer in structure {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {}
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
pub fn verify(ctx: &SqContext, policy: &dyn Policy, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<gmime::SignatureList> {

    // load certs
 
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

    Ok(helper.result)
}
pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<i32> {

    let helper = DHelper::new(&ctx);
    let mut decryptor = DecryptorBuilder::from_reader(input)?
        // .mapping(hex)
        .with_policy(&policy, None, helper)
        .context("Decryption failed")?;

    io::copy(&mut decryptor, output).context("Decryption failed")?;

    let helper = decryptor.into_helper();
    if let Some(dumper) = helper.dumper.as_ref() {
        dumper.flush(&mut io::stderr())?;
    }
    helper.vhelper.print_status();
    Ok(0)
}

fn get_primary_keys<C>(certs: &[C], p: &dyn Policy,
                       private_key_store: Option<&str>,)
                       // timestamp: Option<SystemTime>,
                       // options: Option<&[GetKeysOptions]>)
    -> Result<Box<dyn crypto::Signer + Send + Sync>>
    where C: std::borrow::Borrow<Cert>
{
    get_keys(certs, p, private_key_store, timestamp,
             KeyType::Primary, options)
}

pub fn encrypt(ctx: &SqContext, policy: &dyn Policy, flags: EncryptFlags,
    sign: bool, userid: Option<&str>, recipients: &[&str],
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync))
        -> openpgp::Result<i32> {

    if recipients.len() == 0 {
        return Err(anyhow::anyhow!(
            "Not recipient"));
    }
    

    let mode = KeyFlags::empty()
            .set_storage_encryption()
            .set_transport_encryption();

    let mut recipient_subkeys: Vec<Recipient> = Vec::new();
    for id in recipients.iter() {
        let mut count = 0;
        let cert = get_cert(id);
        for key in cert.keys().with_policy(policy, None).alive().revoked(false)
            .key_flags(&mode).supported().map(|ka| ka.key())
        {
            recipient_subkeys.push(key.into());
            count += 1;
        }
    }

    let message = Message::new(output);
    let encryptor = Encryptor::for_recipients(message, recipient_subkeys);

    let mut sink = encryptor.build()
        .context("Failed to create encryptor")?;

    if flags != EncryptFlags::NoCompress {
        sink = Compressor::new(sink).algo(CompressionAlgorithm::Zip).build()?;
    }

    if sign {
        // let userid = userid.unwrap_or_else
        if let Some(userid) = userid {
            let mut signers = get_signing_key()?;
            // &opts.signers, opts.policy, opts.private_key_store, opts.time, None)?;
            let mut signer = Signer::new(sink, signers);
        }
        for r in recipients.iter() {
            signer = signer.add_intended_recipient(r);
        }
        sink = signer.build()?;
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
