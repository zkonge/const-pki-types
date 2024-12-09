#![no_std]
pub use rustls_pki_types::{Der, TrustAnchor};

// parse the DER encoded TLV
// input is a slice of bytes, includes the DER encoded TLV
// output is (remaining bytes, (tag, length, value))
const fn read_tlv(der: &[u8]) -> (&[u8], (u8, usize, &[u8])) {
    let [tag, first_len_byte, rem @ ..] = der else {
        panic!("length too short");
    };

    if *first_len_byte & 0x80 == 0 {
        let (value, rem) = rem.split_at(*first_len_byte as usize);
        return (rem, (*tag, *first_len_byte as usize, value));
    }

    let len_len = *first_len_byte & 0x7f;
    let (len_bytes, rem) = rem.split_at(len_len as usize);

    let len: usize = match len_bytes {
        [a] => u32::from_be_bytes([0, 0, 0, *a]) as _,
        [a, b] => u32::from_be_bytes([0, 0, *a, *b]) as _,
        [a, b, c] => u32::from_be_bytes([0, *a, *b, *c]) as _,
        [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]) as _,
        #[cfg(target_pointer_width = "64")]
        [a, b, c, d, e] => u64::from_be_bytes([0, 0, 0, *a, *b, *c, *d, *e]) as _,
        #[cfg(target_pointer_width = "64")]
        [a, b, c, d, e, f] => u64::from_be_bytes([0, 0, *a, *b, *c, *d, *e, *f]) as _,
        #[cfg(target_pointer_width = "64")]
        [a, b, c, d, e, f, g] => u64::from_be_bytes([0, *a, *b, *c, *d, *e, *f, *g]) as _,
        #[cfg(target_pointer_width = "64")]
        [a, b, c, d, e, f, g, h] => u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]) as _,
        _ => panic!("unsupported length"),
    };

    let (value, rem) = rem.split_at(len as usize);

    (rem, (*tag, len as usize, value))
}

/// Parse a DER-encoded X.509 certificate into the [`TrustAnchor`].
///
/// It is very similar to the [`webpki::anchor_from_trusted_cert`],
/// and supposed to be used in a const context, not the runtime.
/// Be aware that this function is not fully validating the certificate.
/// Only call it when you trust the input certificate.
pub const fn anchor_from_trusted_cert(cert: &[u8]) -> TrustAnchor<'_> {
    // parse Certificate
    let (&[], (0x30, _, cert)) = read_tlv(cert) else {
        panic!("invalid DER");
    };

    // parse TBSCertificate
    let (_, (0x30, _, tbs_cert)) = read_tlv(cert) else {
        panic!("invalid TBSCertificate");
    };

    // skip version
    let (rem, (0xa0, _, _)) = read_tlv(tbs_cert) else {
        panic!("invalid version");
    };

    // skip serial number
    let (rem, (0x02, _, _)) = read_tlv(rem) else {
        panic!("invalid CertificateSerialNumber");
    };

    // skip signature
    let (rem, (0x30, _, _)) = read_tlv(rem) else {
        panic!("invalid AlgorithmIdentifier");
    };

    // skip issuer
    let (rem, (0x30, _, _)) = read_tlv(rem) else {
        panic!("invalid Issuer");
    };

    // skip validity
    let (rem, (0x30, _, _)) = read_tlv(rem) else {
        panic!("invalid Validity");
    };

    // extract subject
    let (rem, (0x30, _, subject)) = read_tlv(rem) else {
        panic!("invalid Subject");
    };

    // extract subject public key info
    let (_, (0x30, _, spki)) = read_tlv(rem) else {
        panic!("invalid SubjectPublicKeyInfo");
    };

    TrustAnchor {
        subject: Der::from_slice(subject),
        subject_public_key_info: Der::from_slice(spki),
        name_constraints: None,
    }
}

#[cfg(test)]
mod tests {
    use webpki_root_certs::TLS_SERVER_ROOT_CERTS;
    use webpki_roots::TLS_SERVER_ROOTS;

    use super::*;

    #[test]
    fn test_anchors_from_webpki_roots() {
        for (cert, ta) in TLS_SERVER_ROOT_CERTS.iter().zip(TLS_SERVER_ROOTS) {
            let my_anchor = anchor_from_trusted_cert(cert);
            let mut std_anchor = ta.clone();
            // we won't check the name constraints
            std_anchor.name_constraints = None;

            assert_eq!(my_anchor, std_anchor);
        }
    }
}
