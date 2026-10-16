//! Composite ML-DSA-87 with ECDSA/NIST P-384 public keys (`ssh-mldsa87-p384`).
//!
//! Described in `draft-ietf-sshm-composite-sigs-00` § 4.

use crate::{Error, Result};
use alloc::boxed::Box;
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use sec1::consts::U48;

/// Composite ML-DSA-87 with ECDSA/NIST P-384 public key (`ssh-mldsa87-p384`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Mldsa87P384PublicKey {
    /// FIPS 204 ML-DSA-87 public key bytes (2592 bytes).
    mldsa: Box<[u8; Self::MLDSA_PUBLIC_KEY_SIZE]>,

    /// Uncompressed SEC1-encoded NIST P-384 public key point (97 bytes).
    ecdsa: sec1::EncodedPoint<U48>,
}

impl Mldsa87P384PublicKey {
    /// Size of an encoded ML-DSA-87 public key in bytes.
    pub const MLDSA_PUBLIC_KEY_SIZE: usize = 2592;

    /// Size of an uncompressed SEC1-encoded NIST P-384 public key point in bytes.
    pub const ECDSA_PUBLIC_KEY_SIZE: usize = 97;

    /// Create a new `ssh-mldsa87-p384` public key from its ML-DSA-87 and ECDSA P-384 components.
    ///
    /// # Errors
    /// Returns [`Error::FormatEncoding`] if `ecdsa` is not a 97-byte uncompressed SEC1 point.
    pub fn new(
        mldsa: [u8; Self::MLDSA_PUBLIC_KEY_SIZE],
        ecdsa: sec1::EncodedPoint<U48>,
    ) -> Result<Self> {
        if ecdsa.as_bytes().len() != Self::ECDSA_PUBLIC_KEY_SIZE
            || ecdsa.tag() != sec1::point::Tag::Uncompressed
        {
            return Err(Error::FormatEncoding);
        }

        Ok(Self {
            mldsa: Box::new(mldsa),
            ecdsa,
        })
    }

    /// Parse an `ssh-mldsa87-p384` public key from raw component slices.
    ///
    /// # Errors
    /// - Returns [`Error::Encoding`] if `mldsa` is not [`Self::MLDSA_PUBLIC_KEY_SIZE`] bytes.
    /// - Returns [`Error::Ecdsa`] or [`Error::FormatEncoding`] if `ecdsa_sec1` is not a valid
    ///   uncompressed SEC1 P-384 point.
    pub fn from_components(mldsa: &[u8], ecdsa_sec1: &[u8]) -> Result<Self> {
        let mldsa: [u8; Self::MLDSA_PUBLIC_KEY_SIZE] = mldsa.try_into()?;
        let ecdsa = sec1::EncodedPoint::<U48>::from_bytes(ecdsa_sec1)?;
        Self::new(mldsa, ecdsa)
    }

    /// Borrow the 2592-byte ML-DSA-87 public key.
    #[must_use]
    pub fn mldsa(&self) -> &[u8; Self::MLDSA_PUBLIC_KEY_SIZE] {
        &self.mldsa
    }

    /// Borrow the SEC1-encoded NIST P-384 public key point.
    #[must_use]
    pub fn ecdsa(&self) -> &sec1::EncodedPoint<U48> {
        &self.ecdsa
    }

    /// Borrow the raw SEC1-encoded NIST P-384 public key bytes (97 bytes).
    #[must_use]
    pub fn ecdsa_sec1_bytes(&self) -> &[u8] {
        self.ecdsa.as_bytes()
    }
}

impl Decode for Mldsa87P384PublicKey {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            let mut mldsa = [0u8; Self::MLDSA_PUBLIC_KEY_SIZE];
            reader.read(&mut mldsa)?;

            let mut ecdsa_buf = [0u8; Self::ECDSA_PUBLIC_KEY_SIZE];
            let ecdsa_bytes = reader.read_byten(&mut ecdsa_buf)?;
            if ecdsa_bytes.len() != Self::ECDSA_PUBLIC_KEY_SIZE {
                return Err(encoding::Error::Length.into());
            }

            let ecdsa = sec1::EncodedPoint::<U48>::from_bytes(ecdsa_bytes)?;
            reader.ensure_finished()?;
            Self::new(mldsa, ecdsa)
        })
    }
}

impl Encode for Mldsa87P384PublicKey {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            4,
            Self::MLDSA_PUBLIC_KEY_SIZE,
            self.ecdsa.as_bytes().encoded_len()?,
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        [
            Self::MLDSA_PUBLIC_KEY_SIZE,
            self.ecdsa.as_bytes().encoded_len()?,
        ]
        .checked_sum()?
        .encode(writer)?;
        writer.write(self.mldsa.as_slice())?;
        self.ecdsa.as_bytes().encode(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Mldsa87P384PublicKey;
    use crate::{Algorithm, public::KeyData};
    use encoding::{Decode, Encode};

    fn sample_uncompressed_p384_sec1() -> [u8; Mldsa87P384PublicKey::ECDSA_PUBLIC_KEY_SIZE] {
        let mut sec1 = [0x11u8; Mldsa87P384PublicKey::ECDSA_PUBLIC_KEY_SIZE];
        sec1[0] = 0x04;
        sec1
    }

    #[test]
    fn algorithm_and_certificate_strings() {
        let alg = Algorithm::new("ssh-mldsa87-p384").unwrap();
        assert_eq!(alg, Algorithm::Mldsa87P384);
        assert!(alg.is_mldsa87_p384());
        assert_eq!(alg.as_str(), "ssh-mldsa87-p384");
        assert_eq!(
            alg.to_certificate_type(),
            "ssh-mldsa87-p384-cert-v01@openssh.com"
        );
        assert_eq!(
            Algorithm::new_certificate("ssh-mldsa87-p384-cert-v01@openssh.com").unwrap(),
            Algorithm::Mldsa87P384
        );
    }

    #[test]
    fn public_key_wire_roundtrip_and_validation() {
        let mldsa = [0x42u8; Mldsa87P384PublicKey::MLDSA_PUBLIC_KEY_SIZE];
        let ecdsa_sec1 = sample_uncompressed_p384_sec1();
        let pk = Mldsa87P384PublicKey::from_components(&mldsa, &ecdsa_sec1).unwrap();
        assert_eq!(pk.mldsa(), &mldsa);
        assert_eq!(pk.ecdsa_sec1_bytes(), &ecdsa_sec1);

        let key_data = KeyData::from(pk.clone());
        assert!(key_data.is_mldsa87_p384());
        assert_eq!(key_data.mldsa87_p384(), Some(&pk));
        assert_eq!(key_data.algorithm(), Algorithm::Mldsa87P384);

        let encoded = key_data.encode_vec().unwrap();
        // 4 + 16 ("ssh-mldsa87-p384") + 4 (composite len = 2693) + 2592 + 4 + 97 = 2717
        assert_eq!(encoded.len(), 2717);
        assert_eq!(&encoded[20..24], &2693u32.to_be_bytes());

        let decoded = KeyData::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded, key_data);

        // Reject trailing byte inside composite_public_key prefix
        let mut with_trailing = encoded.clone();
        with_trailing[20..24].copy_from_slice(&2694u32.to_be_bytes());
        with_trailing.push(0x00);
        assert!(KeyData::decode(&mut with_trailing.as_slice()).is_err());

        // Reject compressed P-384 point (49 bytes starting with 0x02)
        let mut compressed = [0x11u8; 49];
        compressed[0] = 0x02;
        assert!(Mldsa87P384PublicKey::from_components(&mldsa, &compressed).is_err());
    }
}
