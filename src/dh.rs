use super::ubig::Ubig;

const NIST_DH_P: [u8; 192] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x27, 0x73, 0x23, 0xca, 0x08, 0x6c, 0x74, 0xf1,
    0x04, 0x98, 0xbc, 0x4a, 0x4e, 0x35, 0x0c, 0x67, 0x6d, 0x96, 0x96, 0x70, 0x07, 0x29, 0xd5, 0x9e,
    0xbb, 0x52, 0x85, 0x20, 0x56, 0xf3, 0x62, 0x1c, 0x96, 0xad, 0xa3, 0xdc, 0x23, 0x5d, 0x65, 0x83,
    0x5f, 0xcf, 0x24, 0xfd, 0xa8, 0x3f, 0x16, 0x69, 0x9a, 0xd3, 0x55, 0x1c, 0x36, 0x48, 0xda, 0x98,
    0x05, 0xbf, 0x63, 0xa1, 0xb8, 0x7c, 0x00, 0xc2, 0x3d, 0x5b, 0xe4, 0xec, 0x51, 0x66, 0x28, 0x49,
    0xe6, 0x1f, 0x4b, 0x7c, 0x11, 0x24, 0x9f, 0xae, 0xa5, 0x9f, 0x89, 0x5a, 0xfb, 0x6b, 0x38, 0xee,
    0xed, 0xb7, 0x06, 0xf4, 0xb6, 0x5c, 0xff, 0x0b, 0x6b, 0xed, 0x37, 0xa6, 0xe9, 0x42, 0x4c, 0xf4,
    0xc6, 0x7e, 0x5e, 0x62, 0x76, 0xb5, 0x85, 0xe4, 0x45, 0xc2, 0x51, 0x6d, 0x6d, 0x35, 0xe1, 0x4f,
    0x37, 0x14, 0x5f, 0xf2, 0x6d, 0x0a, 0x2b, 0x30, 0x1b, 0x43, 0x3a, 0xcd, 0xb3, 0x19, 0x95, 0xef,
    0xdd, 0x04, 0x34, 0x8e, 0x79, 0x08, 0x4a, 0x51, 0x22, 0x9b, 0x13, 0x3b, 0xa6, 0xbe, 0x0b, 0x02,
    0x74, 0xcc, 0x67, 0x8a, 0x08, 0x4e, 0x02, 0x29, 0xd1, 0x1c, 0xdc, 0x80, 0x8b, 0x62, 0xc6, 0xc4,
    0x34, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const NIST_DH_G: [u8; 1] = [2];

pub fn nist_dh_p() -> Ubig {
    Ubig::from(NIST_DH_P.as_ref())
}

pub fn nist_dh_public(private: &[u8]) -> Vec<u8> {
    let p = Ubig::from(NIST_DH_P.as_ref());
    let g = Ubig::from(NIST_DH_G.as_ref());

    let q = Ubig::from(private);

    Ubig::modexp(g, q, p).into()
}

pub fn nist_dh_secret(other_public: &[u8], our_private: &[u8]) -> Vec<u8> {
    let p = Ubig::from(NIST_DH_P.as_ref());
    let g = Ubig::from(other_public);

    let q = Ubig::from(our_private);

    Ubig::modexp(g, q, p).into()
}
