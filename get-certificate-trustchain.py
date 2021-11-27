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
    """Get text information from a PEM encoded certificate."""
    return _process_external(["openssl", "x509", "-text", "-noout"],
                             certificate)


def pkcs7_store_to_pem_chain(store: bytes, format="PEM") -> bytes:
    """Convert a pkcs7 certificate store to a concatenated list of one or
    more X509 PEM certificates."""
    return _process_external(["openssl", "pkcs7", "--print_certs",
                              "-inform", format], store)


def x509_der_to_pem(der_cert):
    """Convert a X509 DER-encoded certificate to a PEM certificate."""
    return _process_external(["openssl", "x509", "-inform", "DER",
                              "-outform", "PEM"], der_cert)


def any_cert_to_x509_pem_chain(cert: bytes) -> bytes:
    """Convert any certificate to a concatenated list containing one or more
    x509 PEM  certificates."""
    if cert.find(b"-----BEGIN CERTIFICATE") != -1:
        # PEM encoded X509 Format
        return cert
    if cert.find(b"-----BEGIN PKCS7") != -1:
        # PEM encoded PKCS7 format
        return pkcs7_store_to_pem_chain(cert, "PEM")

    # DER encoding handling.
    # TODO: Find a way to get the type without trail and error.
    try:
        return x509_der_to_pem(cert)
    except subprocess.CalledProcessError:
        return pkcs7_store_to_pem_chain(cert, "DER")


def x509_chain_to_individual_pem_certs(cert_chain: bytes) -> Iterator[bytes]:
    begin_pos = 0
    begin_marker = b"-----BEGIN CERTIFICATE----"
    end_marker = b"-----END CERTIFICATE-----"
    while True:
        begin_pos = cert_chain.find(begin_marker, begin_pos)
        if begin_pos == -1:
            return
        end_pos = cert_chain.find(end_marker, begin_pos)
        if end_pos == -1:
            raise EOFError("Truncated certificate")
        end_pos += len(end_marker)
        yield cert_chain[begin_pos: end_pos] + b"\n"
        begin_pos = end_pos


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


def get_issuer_cert_using_uri(certificate: bytes) -> Optional[bytes]:
    issuer_uri = get_issuer_url(certificate)
    if issuer_uri is None:
        # No issuer URI, this is the root certificate.
        return None
    issuer_cert = retrieve_uri_bytes(issuer_uri)
    return issuer_cert


def get_certificate_chain(certificate: bytes) -> Iterator[bytes]:
    while True:
        # Make sure the certificate is in x509 PEM format. Possibly with
        # multiple certs
        pem_chain = any_cert_to_x509_pem_chain(certificate)
        # Iterate over the pem_chain.
        for certificate in x509_chain_to_individual_pem_certs(pem_chain):
            yield certificate
        # `certificate` is the last certificate from the chain. Get its issuer
        # from an URI.
        certificate = get_issuer_cert_using_uri(certificate)
        if certificate is None:  # No issuer. We have reached the root.
            return


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        "Return all certificates in the chain except the domain cert. "
        "Intermediate certificates are read from the provided certificate if "
        "there are any. The 'CA Issuers - URI' field is used to resolve all "
        "remaning certificates up until the root."
    )
    parser.add_argument("certificate")
    parser.add_argument("-o", "--output", type=str, default=DEFAULT_OUTFILE)
    return parser


def main():
    args = argument_parser().parse_args()
    certificate = Path(args.certificate).read_bytes()
    certificate_chain = get_certificate_chain(certificate)
    # We don't need the domain certificate so skip the first certificate.
    next(certificate_chain)
    with open(args.output, "wb") as output_h:
        for issuer in certificate_chain:
            output_h.write(issuer)


if __name__ == "__main__":
    main()
