# SPDX-License-Identifier: GPL-3.0-or-later
# Author: Xianglong He
# License: GNU General Public License v3.0 or later (GPLv3)

import ssl
import socket
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID
import os

# 从文件读取域名
def load_urls_from_file(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

url_list = load_urls_from_file("domain_list.txt")

def get_certificate(hostname, port=443):
    print(f"Connecting to {hostname}:{port} to retrieve SSL certificate...")
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der_cert = ssock.getpeercert(binary_form=True)
            print(f"Certificate retrieved for {hostname}.")
            return x509.load_der_x509_certificate(der_cert, default_backend())

def extract_subject_info(cert):
    print("Extracting subject information from certificate...")
    subject = cert.subject
    subject_dict = {attr.oid._name: attr.value for attr in subject}
    try:
        alt_names_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        alt_names = alt_names_ext.value.get_values_for_type(x509.DNSName)
        print(f"Found SANs: {alt_names}")
    except x509.ExtensionNotFound:
        alt_names = []
        print("No SANs found in certificate.")
    subject_dict['alt_names'] = alt_names

    # 提取关键用途和扩展字段
    extensions = []
    for ext in cert.extensions:
        if ext.oid == ExtensionOID.KEY_USAGE:
            key_usage = ext.value
            extensions.append(ext)
            print(f"Key Usage: {key_usage}")
        elif ext.oid in [ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.BASIC_CONSTRAINTS]:
            extensions.append(ext)
            print(f"Extension: {ext.oid._name} found.")

    subject_dict['extensions'] = extensions
    print(f"Extracted subject fields: {subject_dict}")
    return subject_dict

def generate_csr(subject_info, key):
    print("Generating CSR with extracted subject info...")
    name_attributes = []
    if 'countryName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_info['countryName']))
    if 'stateOrProvinceName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_info['stateOrProvinceName']))
    if 'localityName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_info['localityName']))
    if 'organizationName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_info['organizationName']))
    if 'organizationalUnitName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_info['organizationalUnitName']))
    if 'commonName' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_info['commonName']))
    if 'emailAddress' in subject_info:
        name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_info['emailAddress']))

    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(name_attributes))

    # 添加 SAN 扩展
    alt_names = subject_info.get('alt_names', [])
    if alt_names:
        san_list = [x509.DNSName(name) for name in alt_names]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )

    # 添加原证书中的扩展字段
    extensions = subject_info.get('extensions', [])
    for ext in extensions:
        try:
            builder = builder.add_extension(ext.value, critical=ext.critical)
            print(f"Added extension: {ext.oid._name}")
        except Exception as e:
            print(f"Failed to add extension {ext.oid._name}: {e}")

    csr = builder.sign(key, hashes.SHA256(), default_backend())
    print("CSR generation complete.")
    return csr

def save_key_and_csr(key, csr, domain):
    key_file = f"{domain}_key.pem"
    csr_file = f"{domain}_csr.pem"
    print(f"Saving private key to {key_file}...")
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"Saving CSR to {csr_file}...")
    with open(csr_file, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))
    print(f"Saved: {key_file}, {csr_file}")

for url in url_list:
    hostname = urlparse(url).hostname if url.startswith("http") else url
    print(f"\nProcessing: {hostname}")
    try:
        cert = get_certificate(hostname)
        subject_info = extract_subject_info(cert)

        print("Generating RSA private key...")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

        csr = generate_csr(subject_info, key)

        save_key_and_csr(key, csr, hostname)
    except Exception as e:
        print(f"Error processing {hostname}: {e}")
