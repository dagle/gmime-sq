use std::{collections::{HashMap, hash_map::Entry, HashSet}, fs::{File, self}, io::{self, Read, Write}, time::SystemTime, str::FromStr, borrow::Borrow};
 
extern crate sequoia_openpgp as openpgp;
use gmime::{traits::{SignatureListExt, SignatureExt, CertificateExt, DecryptResultExt, CertificateListExt}, PubKeyAlgo, DigestAlgo, DecryptFlags, EncryptFlags};
use openpgp::{Fingerprint, types::{SignatureType, PublicKeyAlgorithm, HashAlgorithm, KeyFlags, CompressionAlgorithm, SymmetricAlgorithm}, parse::stream::{VerifierBuilder, VerificationHelper, MessageStructure, MessageLayer, DetachedVerifierBuilder, VerificationResult, DecryptorBuilder, DecryptionHelper}, KeyID, cert::{prelude::ValidErasedKeyAmalgamation, amalgamation::{ValidAmalgamation, key::PrimaryKey}}, crypto::{self, Password, Decryptor}, fmt::hex};
use openpgp::serialize::stream::*;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;
use openpgp::serialize::stream::Message;
use openpgp::serialize::Serialize;
use anyhow::Context;
extern crate chrono;
use chrono::offset::Utc;
use chrono::DateTime;

use openpgp::cert::{
        Cert,
        CertParser,
    };

use openpgp::parse::Parse;

use super::{imp::SqContext, query::Query};

struct autocrypt {
    keyid: String,
}

pub fn verify(ctx: &SqContext, policy: &dyn Policy, _flags: gmime::VerifyFlags, input: &mut (dyn io::Read + Send + Sync),
    sigstream: Option<&mut (dyn io::Read + Send + Sync)>, output: Option<&mut (dyn io::Write + Send + Sync)>) -> openpgp::Result<Option<gmime::SignatureList>> {

    // TODO: call autocrypt
}


pub fn decrypt(ctx: &SqContext, policy: &dyn Policy, flags: DecryptFlags,
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync),
    sk: Option<&str>)
        -> openpgp::Result<gmime::DecryptResult> {

    // decrypt

}

// TODO: Fix flags when the new gir is done
// Then EncryptFlags should be a bitfield
pub fn encrypt(ctx: &SqContext, policy: &dyn Policy, flags: EncryptFlags,
    sign: bool, userid: Option<&str>, recipients: &[&str],
    input: &mut (dyn Read + Send + Sync), output: &mut (dyn Write + Send + Sync))
        -> Result<i32> {

        // TODO: encrypt

    // Ok(0)
}
