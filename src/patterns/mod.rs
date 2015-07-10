use super::endian::AsByteVec;

mod crypto;
mod hash;
mod other;

pub struct Pattern {
    pub algorithm: &'static str,
    pub desc: &'static str,
    pub bytes: &'static AsByteVec,
    pub varname: &'static str,
}


pub fn get_patterns() -> Vec<Pattern> {
    macro_rules! mkpat {
        ($name:expr, $var:expr) => {
            mkpat!($name, $var, stringify!($var))
        };

        ($name:expr, $var:expr, $desc:expr) => {
            Pattern {
                algorithm:  $name,
                desc:       $desc,
                bytes:      & $var as &AsByteVec,
                varname:    stringify!($var),
            }
        };
    };

    vec![
        // Hash algorithms
        mkpat!("SHA-256",           hash::SHA256_CONSTS),
        mkpat!("SHA-512",           hash::SHA512_CONSTS),
        mkpat!("MD5",               hash::MD5_CONSTS),
        mkpat!("CRC32",             hash::CRC32_CONSTS),
        mkpat!("Keccak",            hash::KECCAK_CONSTS),

        // Crypto algorithms
        mkpat!("Blowfish",          crypto::BLOWFISH_P_PERM),
        mkpat!("Blowfish",          crypto::BLOWFISH_S_PERM_0),
        mkpat!("Blowfish",          crypto::BLOWFISH_S_PERM_1),
        mkpat!("Blowfish",          crypto::BLOWFISH_S_PERM_2),
        mkpat!("Blowfish",          crypto::BLOWFISH_S_PERM_3),
        mkpat!("DES",               crypto::DES_IP),
        mkpat!("DES",               crypto::DES_FP),
        mkpat!("DES",               crypto::DES_PC1),
        mkpat!("DES",               crypto::DES_PC2),
        mkpat!("DES",               crypto::DES_E),
        mkpat!("DES",               crypto::DES_P),
        mkpat!("DES",               crypto::DES_SBOX_0),
        mkpat!("DES",               crypto::DES_SBOX_1),
        mkpat!("DES",               crypto::DES_SBOX_2),
        mkpat!("DES",               crypto::DES_SBOX_3),
        mkpat!("DES",               crypto::DES_SBOX_4),
        mkpat!("DES",               crypto::DES_SBOX_5),
        mkpat!("DES",               crypto::DES_SBOX_6),
        mkpat!("DES",               crypto::DES_SBOX_7),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TE0),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TE1),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TE2),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TE3),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TE4),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TD0),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TD1),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TD2),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TD3),
        mkpat!("Rijndael",          crypto::RIJNDAEL_TD4),

        // Other things
        mkpat!("PKCS MD2",          other::PKCS_DIGEST_MD2),
        mkpat!("PKCS MD5",          other::PKCS_DIGEST_MD5),
        mkpat!("PKCS RIPEMD160",    other::PKCS_DIGEST_RIPEMD160),
        mkpat!("PKCS Tiger",        other::PKCS_DIGEST_TIGER),
        mkpat!("PKCS SHA256",       other::PKCS_DIGEST_SHA256),
        mkpat!("PKCS SHA384",       other::PKCS_DIGEST_SHA384),
        mkpat!("PKCS SHA512",       other::PKCS_DIGEST_SHA512),
    ]
}
