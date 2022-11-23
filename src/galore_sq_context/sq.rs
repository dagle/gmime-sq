use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::File, io::{self, Read, Write}};
 
extern crate sequoia_openpgp as openpgp;
use openpgp::{Fingerprint, armor, types::SignatureType, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder}, KeyID};
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

struct GMimeCryptoContext {
    path: String,
}

// TODO we should do more than this, what should we match on
fn cmp_opt<T: PartialEq>(o1: Option<T>, o2: Option<T>) -> bool {
    if let Some(v1) = o1 {
        if let Some(v2) = o2 {
            return v1 == v2
        }
    }
    false
}

fn match_(ui: &UserID, vuid: &UserID) -> bool {
    cmp_opt(vuid.email().unwrap_or(None), ui.email().unwrap_or(None))
}

fn match_id<'a>(ui: UserID, certs: &Vec<Cert>) -> Option<&Cert>
where {
    for cert in certs.into_iter() {
        if cert.userids().any(|vuid| match_(&ui, vuid.component())) {
            return Some(cert)
        }
    }
    None
}

// static int gpg_export_keys (GMimeCryptoContext *ctx, const char *keys[],
// 			    GMimeStream *ostream, GError **err);
fn sq_export_keys(ctx: GMimeCryptoContext, keys: Vec<String>, 
    output: &mut (dyn io::Write + Send + Sync))
    -> openpgp::Result<()> {
    let userids = keys.into_iter().map(|key| UserID::from(key));

    // TODO don't use filter_map
    let certs: Vec<Cert> = CertParser::from_file(ctx.path)?.filter_map(|cert| cert.ok()).collect();
    let mut message = Message::new(output);
    message = Armorer::new(message).kind(armor::Kind::PublicKey).build()?;
    for uid in userids.into_iter() {
        if let Some(cert) = match_id(uid, &certs) {
            cert.serialize(&mut message)?;
        } else {
            // TODO should we do this or should we just skip and return
            // a number with all keys we exported?
            return Err(anyhow::anyhow!("No keys were found"));
        }
    }
    message.finalize()?;
    Ok(())
}

// static int gpg_import_keys (GMimeCryptoContext *ctx, GMimeStream *istream, GError **err);
fn sq_import_keys(ctx: GMimeCryptoContext, input: &mut (dyn io::Read + Send + Sync))
    -> openpgp::Result<()> {
    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();
    let mut output = File::open(ctx.path)?;
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

    for fpr in fingerprints.iter() {
        if let Some(Some(cert)) = certs.get(fpr) {
            cert.serialize(&mut output)?;
        }
    }
    Ok(())
}

fn clearsign(policy: &dyn Policy,
        mut output: impl Write + Send + Sync, mut input: impl Read + Send + Sync, tsk: &openpgp::Cert)
    -> openpgp::Result<()>
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
 
    Ok(())
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
fn sign_helper(policy: &dyn Policy, detach: bool,
        output: impl Write + Send + Sync, input: impl Read + Send + Sync, tsk: &openpgp::Cert)
    -> openpgp::Result<i32> {
    if detach {
        sign_detach(policy, output, input, tsk)?;
    } else {
        clearsign(policy, output, input, tsk)?;
    }
    Ok(0)
}
// static int gpg_sign (GMimeCryptoContext *ctx, gboolean detach, const char *userid,
// 		     GMimeStream *istream, GMimeStream *ostream, GError **err);
// detached means: should we only return signature and for use in create a g_mime_multipart_signed
// otherwise we create a message with both of them
fn sq_sign(ctx: GMimeCryptoContext, detached: bool, userid: String, input: &mut (dyn io::Read + Send + Sync)
    , output: &mut (dyn io::Write + Send + Sync)) -> openpgp::Result<()> {
    let policy = &P::new();
    // XXX remove this!
    let tsk = generate()?;

    if detached {
        sign_detach(policy, output, input, &tsk)?;
    } else {
        clearsign(policy, output, input, &tsk)?;
    }
    Ok(())
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
    ctx: &'a GMimeCryptoContext,
    
    // idk, number of signatures needing to pass
    // maybe not do this an pass that up to gmime
    // signatures: usize,
    certs: Option<Vec<Cert>>,

    labels: HashMap<KeyID, String>,
    trusted: HashSet<KeyID>,
    result: Option<Vec<GMimeSig>>,
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
    fn new(ctx: &'a GMimeCryptoContext)
           -> Self {
        VHelper {
            // config: config.clone(),
            ctx,
            // TODO read cert from ctx.path
            certs: None,
            labels: HashMap::new(),
            trusted: HashSet::new(),
            result: None,
            // good_signatures: 0,
            // good_checksums: 0,
            // unknown_checksums: 0,
            // bad_signatures: 0,
            // bad_checksums: 0,
            // broken_signatures: 0,
        }
    }
}
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

struct GMimeSig {
    status: i32,
    cert: Cert,
    created: i32,
    expire: i32,
}

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
fn sq_verify(ctx: GMimeCryptoContext, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<()> {
 
    let policy = &P::new();
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
    // return helper.results

    Ok(())
}


// static int gpg_encrypt (GMimeCryptoContext *ctx, gboolean sign, const char *userid, GMimeEncryptFlags flags,
// 			GPtrArray *recipients, GMimeStream *istream, GMimeStream *ostream, GError **err);
//
// flags are policy?
// sign? run sign before 
// userid => cert to sign
// recipients => certs to encrypt
// istream is plain text
// outstream is sink
// error is result
// 
// fn encrypt(ctx: GMimeCryptoContext, sign: bool, userid: String, recipients: Vec<String>,
//            input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync)) 
//            -> openpgp::Result<()> {
//     let policy = &P::new();
//
//     let recipients =
//         recipient.keys().with_policy(policy, None).supported().alive().revoked(false)
//         .for_transport_encryption();
//  
//     // Start streaming an OpenPGP message.
//     // TODO signing etc, look in sq/encrypt
//     let message = Message::new(output);
//  
//     // We want to encrypt a literal data packet.
//     let message = Encryptor::for_recipients(message, recipients)
//         .build()?;
//  
//     // Emit a literal data packet.
//     let mut message = LiteralWriter::new(message).build()?;
//  
//     // Encrypt the data.
//     io::copy(input, &mut message);
//  
//     // Finalize the OpenPGP message to make sure that all data is
//     message.finalize()?;
//  
//     Ok(())
// }

fn generate() -> openpgp::Result<openpgp::Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()?;
 
    // Save the revocation certificate somewhere.
 
    Ok(cert)
}
