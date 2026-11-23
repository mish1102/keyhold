import pytest

from keyhold import totp

SHA1_SEED = b"12345678901234567890"
SHA256_SEED = b"12345678901234567890123456789012"
SHA512_SEED = b"1234567890123456789012345678901234567890123456789012345678901234"

# RFC 6238 appendix B
VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


@pytest.mark.parametrize("at,sha1,sha256,sha512", VECTORS)
def test_rfc6238_vectors(at, sha1, sha256, sha512):
    assert totp.code(totp.OtpSpec(SHA1_SEED, digits=8, algorithm="SHA1"), at) == sha1
    assert totp.code(totp.OtpSpec(SHA256_SEED, digits=8, algorithm="SHA256"), at) == sha256
    assert totp.code(totp.OtpSpec(SHA512_SEED, digits=8, algorithm="SHA512"), at) == sha512


def test_parse_plain_base32_secret_with_spaces_and_lowercase():
    spec = totp.parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
    assert spec.secret == SHA1_SEED
    assert (spec.digits, spec.period, spec.algorithm) == (6, 30, "SHA1")


def test_parse_base32_secret_without_padding():
    # "hello" -> NBSWY3DP (no padding needed); "hi" -> NBUQ==== needs padding
    assert totp.parse("NBUQ").secret == b"hi"


def test_parse_otpauth_uri():
    uri = ("otpauth://totp/ACME%20Co:john@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
           "&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60")
    spec = totp.parse(uri)
    assert spec.secret == SHA1_SEED
    assert spec.issuer == "ACME Co"
    assert spec.account == "john@example.com"
    assert (spec.digits, spec.period, spec.algorithm) == (8, 60, "SHA256")


@pytest.mark.parametrize("bad", [
    "", "   ", "not base32 !!!", "otpauth://hotp/x?secret=GEZDGNBV&counter=1",
    "otpauth://totp/x", "otpauth://totp/x?secret=GEZDGNBV&digits=12",
    "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5", "otpauth://totp/x?secret=GEZDGNBV&period=0",
])
def test_invalid_values_raise_value_error(bad):
    with pytest.raises(ValueError):
        totp.parse(bad)


def test_seconds_remaining_counts_down_within_period():
    spec = totp.OtpSpec(SHA1_SEED)
    assert totp.seconds_remaining(spec, 60.0) == 30
    assert totp.seconds_remaining(spec, 61.0) == 29
    assert totp.seconds_remaining(spec, 89.5) == 1


def test_format_code_groups_digits():
    assert totp.format_code("911861") == "911 861"
    assert totp.format_code("94287082") == "9428 7082"
    assert totp.format_code("1234567") == "1234 567"
