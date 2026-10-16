//! Composite ML-DSA-87 with ECDSA/NIST P-384 private keys (`ssh-mldsa87-p384`).
//!
//! Described in `draft-ietf-sshm-composite-sigs-00` § 4.

use super::EcdsaPrivateKey;
use crate::{Error, Result, public, public::Mldsa87P384PublicKey};
use core::fmt;
use ctutils::{Choice, CtEq};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
#[cfg(feature = "mldsa")]
use p384::elliptic_curve::sec1::ToSec1Point;
use zeroize::Zeroizing;

#[cfg(all(feature = "mldsa", feature = "rand_core"))]
use {cipher::cipher::common::Generate, rand_core::CryptoRng};

/// Composite ML-DSA-87 with ECDSA/NIST P-384 private/public keypair (`ssh-mldsa87-p384`).
#[derive(Clone)]
pub struct Mldsa87P384Keypair {
    /// Public key.
    public: Mldsa87P384PublicKey,

    /// FIPS 204 32-byte ML-DSA-87 seed $\xi$.
    mldsa_seed: Zeroizing<[u8; Self::MLDSA_SEED_SIZE]>,

    /// ECDSA NIST P-384 private scalar.
    ecdsa_private: EcdsaPrivateKey<48>,
}

impl Mldsa87P384Keypair {
    /// Size of an ML-DSA-87 private seed in bytes.
    pub const MLDSA_SEED_SIZE: usize = 32;

    /// Size of an ECDSA NIST P-384 private scalar in bytes.
    pub const ECDSA_SCALAR_SIZE: usize = 48;

    /// Create a new `ssh-mldsa87-p384` keypair from public and private components.
    ///
    /// When the `mldsa` feature is enabled, validates that `public` matches the public keys
    /// derived from `mldsa_seed` and `ecdsa_private`.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if `mldsa` feature is enabled and the private components are
    /// invalid or do not match `public`.
    pub fn new(
        public: Mldsa87P384PublicKey,
        mldsa_seed: [u8; Self::MLDSA_SEED_SIZE],
        ecdsa_private: EcdsaPrivateKey<48>,
    ) -> Result<Self> {
        let mldsa_seed = Zeroizing::new(mldsa_seed);

        #[cfg(feature = "mldsa")]
        {
            let derived_public = derive_public_key(&mldsa_seed, &ecdsa_private)?;
            if public != derived_public {
                return Err(Error::Crypto);
            }
        }

        Ok(Self {
            public,
            mldsa_seed,
            ecdsa_private,
        })
    }

    /// Derive the public key from the private components and construct an `Mldsa87P384Keypair`.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if `ecdsa_private` is not a valid P-384 scalar.
    #[cfg(feature = "mldsa")]
    pub fn from_private_components(
        mldsa_seed: [u8; Self::MLDSA_SEED_SIZE],
        ecdsa_private: EcdsaPrivateKey<48>,
    ) -> Result<Self> {
        let mldsa_seed = Zeroizing::new(mldsa_seed);
        let public = derive_public_key(&mldsa_seed, &ecdsa_private)?;

        Ok(Self {
            public,
            mldsa_seed,
            ecdsa_private,
        })
    }

    /// Generate a random `ssh-mldsa87-p384` keypair.
    ///
    /// # Errors
    /// Returns [`Error::Crypto`] if key generation fails.
    #[cfg(all(feature = "mldsa", feature = "rand_core"))]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Result<Self> {
        let mut mldsa_seed = Zeroizing::new([0u8; Self::MLDSA_SEED_SIZE]);
        rng.fill_bytes(&mut *mldsa_seed);
        let ecdsa_secret = p384::SecretKey::generate_from_rng(rng);
        Self::from_private_components(*mldsa_seed, ecdsa_secret.into())
    }

    /// Borrow the public key.
    #[must_use]
    pub fn public(&self) -> &Mldsa87P384PublicKey {
        &self.public
    }

    /// Borrow the 32-byte ML-DSA-87 private seed.
    #[must_use]
    pub fn mldsa_seed(&self) -> &[u8; Self::MLDSA_SEED_SIZE] {
        &self.mldsa_seed
    }

    /// Borrow the ECDSA NIST P-384 private key scalar.
    #[must_use]
    pub fn ecdsa_private(&self) -> &EcdsaPrivateKey<48> {
        &self.ecdsa_private
    }
}

#[cfg(feature = "mldsa")]
fn derive_public_key(
    mldsa_seed: &[u8; Mldsa87P384Keypair::MLDSA_SEED_SIZE],
    ecdsa_private: &EcdsaPrivateKey<48>,
) -> Result<Mldsa87P384PublicKey> {
    let mldsa_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(mldsa_seed.into());
    let mldsa_pk: [u8; Mldsa87P384PublicKey::MLDSA_PUBLIC_KEY_SIZE] =
        mldsa_sk.as_ref().encode().into();

    let ecdsa_sk =
        p384::SecretKey::from_slice(ecdsa_private.as_slice()).map_err(|_| Error::Crypto)?;
    let ecdsa_pk = ecdsa_sk.public_key().to_sec1_point(false);

    Mldsa87P384PublicKey::new(mldsa_pk, ecdsa_pk)
}

impl CtEq for Mldsa87P384Keypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        Choice::from(u8::from(self.public == other.public))
            & self
                .mldsa_seed
                .as_slice()
                .ct_eq(other.mldsa_seed.as_slice())
            & self.ecdsa_private.ct_eq(&other.ecdsa_private)
    }
}

impl Eq for Mldsa87P384Keypair {}

impl PartialEq for Mldsa87P384Keypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for Mldsa87P384Keypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        let public = Mldsa87P384PublicKey::decode(reader)?;
        let (mldsa_seed, ecdsa_private) = reader.read_prefixed(|reader| {
            let mut mldsa_seed = Zeroizing::new([0u8; Self::MLDSA_SEED_SIZE]);
            reader.read(&mut *mldsa_seed)?;
            let ecdsa_private = EcdsaPrivateKey::<48>::decode(reader)?;
            reader.ensure_finished()?;
            Result::Ok((mldsa_seed, ecdsa_private))
        })?;
        Self::new(public, *mldsa_seed, ecdsa_private)
    }
}

impl Encode for Mldsa87P384Keypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            self.public.encoded_len()?,
            4,
            Self::MLDSA_SEED_SIZE,
            self.ecdsa_private.encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        self.public.encode(writer)?;
        [Self::MLDSA_SEED_SIZE, self.ecdsa_private.encoded_len()?]
            .checked_sum()?
            .encode(writer)?;
        writer.write(self.mldsa_seed.as_slice())?;
        self.ecdsa_private.encode(writer)?;
        Ok(())
    }
}

impl From<Mldsa87P384Keypair> for Mldsa87P384PublicKey {
    fn from(keypair: Mldsa87P384Keypair) -> Mldsa87P384PublicKey {
        keypair.public
    }
}

impl From<&Mldsa87P384Keypair> for Mldsa87P384PublicKey {
    fn from(keypair: &Mldsa87P384Keypair) -> Mldsa87P384PublicKey {
        keypair.public.clone()
    }
}

impl From<&Mldsa87P384Keypair> for public::KeyData {
    fn from(keypair: &Mldsa87P384Keypair) -> public::KeyData {
        public::KeyData::Mldsa87P384(keypair.public.clone())
    }
}

impl fmt::Debug for Mldsa87P384Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mldsa87P384Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::Mldsa87P384Keypair;
    use crate::private::EcdsaPrivateKey;
    #[cfg(not(feature = "mldsa"))]
    use crate::{private::KeypairData, public::Mldsa87P384PublicKey};
    use encoding::{Decode, Encode};

    #[cfg(not(feature = "mldsa"))]
    #[test]
    fn keypair_wire_roundtrip_without_mldsa_feature() {
        let mldsa = [0x22u8; Mldsa87P384PublicKey::MLDSA_PUBLIC_KEY_SIZE];
        let mut ecdsa_sec1 = [0x33u8; Mldsa87P384PublicKey::ECDSA_PUBLIC_KEY_SIZE];
        ecdsa_sec1[0] = 0x04;
        let pk = Mldsa87P384PublicKey::from_components(&mldsa, &ecdsa_sec1).unwrap();
        let seed = [0x55u8; Mldsa87P384Keypair::MLDSA_SEED_SIZE];
        let scalar = EcdsaPrivateKey::<48>::from([0x11u8; 48]);

        let kp = Mldsa87P384Keypair::new(pk, seed, scalar).unwrap();
        let kd = KeypairData::from(kp.clone());
        assert!(kd.is_mldsa87_p384());
        assert_eq!(kd.mldsa87_p384(), Some(&kp));

        let encoded = kd.encode_vec().unwrap();
        let mut slice = encoded.as_slice();
        let alg = crate::Algorithm::decode(&mut slice).unwrap();
        let decoded = KeypairData::decode_as(&mut slice, alg).unwrap();
        assert!(slice.is_empty());
        assert_eq!(decoded, kd);

        // Reject trailing byte inside composite_private_key prefix
        let mut bad = kp.encode_vec().unwrap();
        let priv_len_offset = 4 + 2693;
        let orig_priv_len = u32::from_be_bytes(
            bad[priv_len_offset..priv_len_offset + 4]
                .try_into()
                .unwrap(),
        );
        bad[priv_len_offset..priv_len_offset + 4]
            .copy_from_slice(&(orig_priv_len + 1).to_be_bytes());
        bad.push(0x00);
        assert!(Mldsa87P384Keypair::decode(&mut bad.as_slice()).is_err());
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn keypair_derivation_and_mismatch_rejection() {
        let seed = [0x55u8; Mldsa87P384Keypair::MLDSA_SEED_SIZE];
        let scalar = EcdsaPrivateKey::<48>::from([0x11u8; 48]);
        let kp = Mldsa87P384Keypair::from_private_components(seed, scalar.clone()).unwrap();

        let encoded = kp.encode_vec().unwrap();
        let decoded = Mldsa87P384Keypair::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, kp);

        // Mismatched ML-DSA seed must fail validation in `new`
        let bad_seed = [0x56u8; Mldsa87P384Keypair::MLDSA_SEED_SIZE];
        assert!(Mldsa87P384Keypair::new(kp.public().clone(), bad_seed, scalar).is_err());
    }
}
