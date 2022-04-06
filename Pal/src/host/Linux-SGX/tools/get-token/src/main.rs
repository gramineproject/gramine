use argh::FromArgs;
use failure::{format_err, Error, ResultExt};
use gramine_common::flags::{Flags, Mask, AttrFlags, XFRM, Miscselect};
use sgx_isa::{Attributes, Einittoken, Sigstruct};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use sha2::{Sha256, Digest};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(FromArgs)]
/// Generate the SGX token file for a given SIGSTRUCT (".sig file").
struct GetToken {
    /// path to the input file containing SIGSTRUCT
    #[argh(option, short = 's')]
    sig: PathBuf,

    /// path to the output token file
    #[argh(option, short = 'o')]
    output: PathBuf,

    /// don't display details
    #[argh(switch, short = 'q')]
    quiet: bool,
}

fn main() {
    if let Err(e) = get_token(argh::from_env()) {
        eprintln!("{}", e);
    }
}

fn get_token(args: GetToken) -> Result<()> {
    let data = fs::read(&args.sig)
        .with_context(|e| format!("Couldn't read SIGSTRUCT from {:?}: {}", args.sig, e))?;
    let sigstruct = Sigstruct::try_copy_from(&data).ok_or_else(|| {
        format_err!(
            "Incorrect SIGSTRUCT length: {} (expected {})",
            data.len(),
            Sigstruct::UNPADDED_SIZE
        )
    })?;

    let attributes = Attributes {
        flags: sigstruct.attributes.flags,
        xfrm: get_optional_cpu_features(&sigstruct)?,
    };

    if !args.quiet {
        let mut hasher = Sha256::new();
        hasher.update(sigstruct.modulus);
        let mrsigner = hasher.finalize();

        let date_year = sigstruct.date & 0xffff;
        let date_month = (sigstruct.date >> 16) & 0xff;
        let date_day = (sigstruct.date >> 24) & 0xff;

        println!("Attributes:");
        println!("    mr_enclave:  {}", hex::encode(sigstruct.enclavehash));
        println!("    mr_signer:   {}", hex::encode(mrsigner));
        println!("    isv_prod_id: {}", sigstruct.isvprodid);
        println!("    isv_svn:     {}", sigstruct.isvsvn);
        println!("    attr.flags:  {}", Flags::<AttrFlags>(attributes.flags.bits()));
        println!("    attr.xfrm:   {}", Flags::<XFRM>(attributes.xfrm));
        println!("    mask.flags:  {}", Mask::<AttrFlags>(sigstruct.attributemask[0]));
        println!("    mask.xfrm:   {}", Mask::<XFRM>(sigstruct.attributemask[1]));
        println!("    misc_select: {}", Flags::<Miscselect>(sigstruct.miscselect.bits()));
        println!("    misc_mask:   {}", Mask::<Miscselect>(sigstruct.miscmask));
        println!("    modulus:     {}...", hex::encode(&sigstruct.modulus[0..16]));
        println!("    exponent:    {}", sigstruct.exponent);
        println!("    signature:   {}...", hex::encode(&sigstruct.signature[0..16]));
        println!("    date:        {:04}-{:02}-{:02}", date_year, date_month, date_day);
    }

    let token = generate_token(&sigstruct, attributes)?;

    fs::write(&args.output, &token)
        .with_context(|e| format!("Couldn't write token to {:?}: {}", args.output, e))?;
    Ok(())
}

#[cfg(feature = "oot")]
fn generate_token(sigstruct: &Sigstruct, attrs: Attributes) -> Result<Einittoken> {
    use sgxs::einittoken::EinittokenProvider;
    let mut aesm = aesm_client::AesmClient::new();
    match aesm.token(&sigstruct, attrs, false) {
        Ok(token) => Ok(token),
        Err(err) => {
            use aesm_client::{AesmError, Error};
            use sgx_isa::AttributesFlags;
            match err.downcast::<Error>()? {
                err @ Error::AesmCode(AesmError::GetLicensetokenError_6)
                    if !attrs.flags.contains(AttributesFlags::DEBUG) =>
                {
                    Err(format_err!(
                        "{}\nHint: make sure your enclave signing key has been signed by Intel.\n\
                        This is necessary to run enclaves in production mode.",
                        err
                    ))
                }
                err => Err(err)?,
            }
        }
    }
}

#[cfg(not(feature = "oot"))]
fn generate_token(sigstruct: &Sigstruct, attrs: Attributes) -> Result<Einittoken> {
    let mut token = Einittoken::default();
    // fields read by create_enclave() in sgx_framework.c
    token.attributes = attrs;
    token.maskedmiscselectle = sigstruct.miscselect;
    Ok(token)
}

fn cpuinfo_flags() -> Result<HashSet<String>> {
    let cpuinfo = BufReader::new(File::open("/proc/cpuinfo")?);

    for line in cpuinfo.lines() {
        let line = line?;
        if line.starts_with("flags") {
            let (_, flaglist) = line.split_once(": ")
                .ok_or_else(|| format_err!("Incorrect /proc/cpuinfo formatting"))?;
            return Ok(flaglist.split_whitespace().map(|s| s.to_owned()).collect());
        }
    }

    Err(format_err!("Couldn't find 'flags' field in /proc/cpuinfo"))
}

fn get_optional_cpu_features(sigstruct: &Sigstruct) -> Result<u64> {
    let flags = cpuinfo_flags()?;
    let features = &[
        ("avx", XFRM::AVX),
        ("avx512f", XFRM::AVX512),
        ("mpx", XFRM::MPX),
        ("pku", XFRM::PKRU), // "pku" is not a typo, that's how cpuinfo reports it
        ("amx_tile", XFRM::AMX),
    ];

    let mut xfrm = sigstruct.attributes.xfrm;
    let xfrm_mask = sigstruct.attributemask[1];

    for &(name, bits) in features {
        if flags.contains(name) {
            // If xfrm_mask will let us set the additional bits, then set them.
            let extra_bits = bits & !xfrm;
            if xfrm_mask & extra_bits == 0 {
                xfrm |= bits;
            }
        }
    }

    Ok(xfrm)
}
