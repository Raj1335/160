from parser.ike_parser import _DH, _ENCRYPTION, _INTEGRITY, _PRF


def test_iana_encryption_transform_ids():
    assert {
        2: _ENCRYPTION[2],
        3: _ENCRYPTION[3],
        11: _ENCRYPTION[11],
        12: _ENCRYPTION[12],
        20: _ENCRYPTION[20],
    } == {
        2: "DES",
        3: "3DES",
        11: "NULL",
        12: "AES-CBC",
        20: "AES-GCM",
    }


def test_iana_integrity_transform_ids():
    assert {
        1: _INTEGRITY[1],
        2: _INTEGRITY[2],
        12: _INTEGRITY[12],
        13: _INTEGRITY[13],
        14: _INTEGRITY[14],
    } == {
        1: "HMAC-MD5-96",
        2: "HMAC-SHA1-96",
        12: "HMAC-SHA2-256-128",
        13: "HMAC-SHA2-384-192",
        14: "HMAC-SHA2-512-256",
    }


def test_iana_prf_and_diffie_hellman_transform_ids():
    assert _PRF[5] == "PRF-HMAC-SHA2-256"
    assert _PRF[7] == "PRF-HMAC-SHA2-512"
    assert _DH[14] == "MODP2048"
    assert _DH[31] == "Curve25519"
