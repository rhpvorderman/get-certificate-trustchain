#!/usr/bin/env python3

# Copyright (c) 2021 Ruben Vorderman
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Functions to get the SSL trustchain by parsing information from a
certificate and downloading issuer certificates from the web."""
import argparse
import os
import subprocess
from pathlib import Path
from typing import Iterator, List, Optional
from urllib.request import urlopen

DEFAULT_OUTFILE = "/dev/stdout" if os.path.exists("/dev/stdout") else None


def _process_external(command: List[str], input: bytes) -> bytes:
    """Pipe a bytes input trough a process and receive the stdout as bytes."""
    result = subprocess.run(command, input=input, stderr=subprocess.PIPE,
                            stdout=subprocess.PIPE, check=True)
    return result.stdout


def pem_certificate_to_text(certificate: bytes) -> bytes:
    """Get text information from a PEM encoded certificate"""
    return _process_external(["openssl", "x509", "-text", "-noout"],
                             certificate)


def der_certificate_to_pem(certificate: bytes) -> bytes:
    """Convert a DER encoded certificate to PEM"""
    try:
        return _process_external(["openssl", "x509", "-inform", "DER",
                                  "-outform", "PEM"], certificate)
    except subprocess.CalledProcessError:
        certificates = _process_external(
            ["openssl", "pkcs7", "-print_certs", "-inform", "DER"], certificate
        )
        begin = certificates.find(b"-----BEGIN")
        return certificates[begin:]


def get_issuer_url(certificate: bytes) -> Optional[bytes]:
    """Use the 'CA Issuers - URI' field to get the URI for the issuers
    certificate"""
    certificate_text = pem_certificate_to_text(certificate)
    issuers_uri_field = b"CA Issuers - URI:"
    l_index = certificate_text.find(issuers_uri_field)
    if l_index == -1:  # Issuer not found
        return None
    # Move search position to after the field key
    l_index += len(issuers_uri_field)
    # Find the end of the line
    r_index = certificate_text.find(b"\n", l_index)
    # Ensure there is something on the line. If so, slice the line.
    if r_index != -1 and r_index > l_index:
        return certificate_text[l_index:r_index]
    return None


def retrieve_uri_bytes(uri: bytes) -> bytes:
    """Open a URL and return the bytes from the HTTPResponse"""
    httpresponse = urlopen(uri.decode())
    return httpresponse.read()


def get_certificate_encoding(certificate: bytes):
    """Determine whether a certificate is DER or PEM encoded by looking at
    the starting bytes."""
    if certificate.startswith(b"-----BEGIN"):
        return "PEM"
    else:
        return "DER"


def get_trustchain_from_uri(certificate: bytes) -> Iterator[bytes]:
    """Returns a chain of issuer certificates up to the root certificate."""
    while True:
        issuer_uri = get_issuer_url(certificate)
        if issuer_uri is None:
            # No issuer URI, this is the root certificate.
            return
        issuer_cert = retrieve_uri_bytes(issuer_uri)
        if get_certificate_encoding(issuer_cert) == "DER":
            issuer_cert = der_certificate_to_pem(issuer_cert)
        yield issuer_cert
        # Repeat, but now for the issuer cert.
        certificate = issuer_cert


def get_chained_certificates(certificate: bytes) -> Iterator[bytes]:
    begin_pos = 0
    end_marker = b"-----END CERTIFICATE-----\n"
    while True:
        end_pos = certificate.find(end_marker, begin_pos)
        if end_pos == -1:
            return
        end_pos += len(end_marker)
        yield certificate[begin_pos: end_pos].lstrip(b"\n")
        begin_pos = end_pos


def get_trustchain(certificate: bytes) -> Iterator[bytes]:
    cert_chain = get_chained_certificates(certificate)
    domain_certificate = next(cert_chain)
    issuer_certificate = None
    for issuer_certificate in cert_chain:
        yield issuer_certificate
    last_cert = issuer_certificate or domain_certificate
    for issuer_certificate in get_trustchain_from_uri(last_cert):
        yield issuer_certificate


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "Use the 'CA - Issuers URI' field to download all certificates from "
        "the trust chain."
    )
    parser.add_argument("certificate",
                        help="The certificate for which the trust chain "
                             "should be downloaded.")
    parser.add_argument("-o", "--output", type=str, default=DEFAULT_OUTFILE)
    return parser


def main():
    args = argument_parser().parse_args()
    certificate = Path(args.certificate).read_bytes()
    if get_certificate_encoding(certificate) == "DER":
        certificate = der_certificate_to_pem(certificate)
    with open(args.output, "wb") as output_h:
        for issuer in get_trustchain(certificate):
            output_h.write(issuer)


if __name__ == "__main__":
    main()
