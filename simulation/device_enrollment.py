#!/usr/bin/env python
# 
# A simulation script for simulating the part "A. Device Enrollment" of the SUPnP proposed scheme 
#   which is presented in the paper "Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). 
#   SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE 
#   Internet of Things Journal, 8(14), 11561-11580."
#
# The input for the script is an UPnP XML Description Document of a device. Example usage: 
# ./device_enrollment.py ../upnp/sample/web/tvdevicedesc.xml
#
# The output of the script is the generation of:
#   * CA (Certification Authority) private & public keys.
#   * UCA (UPnP Certification Authority) self-signed certificate, private & public keys.
#   * CP (Control Point) certificate signed by ca, private & public keys.
#   * SD (Service Device) certificate signed by ca, private & public keys.
#   * DSD (Device Specification Document) for SD.
#   * SAD (Service Action Document) for CP.
#
# The CA is the root of trust which its public key should be available on the devices.
# The UCA is an intermediate UPnP CA which its certificate is signed by the CA's private key.
# The UCA signs the certificates of the CP and SD, and also the DSD and SAD documents.
#
# Tested with Python 3.12.
#
import argparse
import datetime
import json
import os
import re
import sys
import xmltodict

from abc import abstractmethod
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509.oid import NameOID
from dataclasses import dataclass


# Constants
# See @CryptoHelper for more crypto related constants.
ENTITIES = [ 'CP', 'SD', 'UCA', 'CA' ]
JSON_INDENT = 4
CERTIFICATE_VALIDITY_DAYS = 365

# Certification Authority (CA) details
CA_COMMON_NAME       = 'Certification Authority'
CA_ORGANIZATION_NAME = 'CA'

# UPnP Certification Authority (UCA) details
UCA_COMMON_NAME       = 'UPnP Certification Authority'
UCA_ORGANIZATION_NAME = 'UCA'

# SD (Service Device) details
SD_COUNTRY_NAME           = 'US'
SD_STATE_OR_PROVINCE_NAME = 'California'
SD_LOCALITY_NAME          = 'San Francisco'
SD_ORGANIZATION_NAME      = 'SD'

# CP (Control Point) details
CP_COUNTRY_NAME           = 'US'
CP_STATE_OR_PROVINCE_NAME = 'California'
CP_LOCALITY_NAME          = 'San Francisco'
CP_ORGANIZATION_NAME      = 'CP'


def error(msg: str) -> None:
    """ Print error message and exit. """
    print("[!] %s" % msg)
    sys.exit(1)


@dataclass
class Details:
    COUNTRY_NAME: str
    STATE_OR_PROVINCE_NAME: str
    LOCALITY_NAME: str
    ORGANIZATION_NAME: str
    
    def subject(self) -> x509.Name: # Generate subject name for certificate
        return x509.Name([
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.COUNTRY_NAME),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.STATE_OR_PROVINCE_NAME),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.LOCALITY_NAME),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.ORGANIZATION_NAME),
        ])


class Entity:
    """ Helper class for entities """
    def __init__(self, type: str) -> None:
        if type not in ENTITIES:
            error("Invalid entity type '%s'. Must be one of %s" % (type, ENTITIES))
        self.type: str = type
        print("[*] Initializing %s.." % self)
        os.makedirs(type, exist_ok=True)
        sk, pk = CryptoHelper.generate_key_pair(type)  # private key, public key
        self.private_key: PrivateKeyTypes = sk
        self.public_key:  PublicKeyTypes  = pk
        self.cert: x509.Certificate
        self.subject: x509.Name = self.generate_subject()
        self.ca = False
    
    @abstractmethod
    def generate_subject(self) -> x509.Name:
        """ Generate subject name for certificate """
        raise NotImplementedError("generate_subject is not implemented.")
      
    def __str__(self) -> str:
        return self.type


class SD(Entity):
    """ Service Device """
    def __init__(self) -> None:
        super().__init__('SD')
        
    def generate_subject(self) -> x509.Name:
        details = Details(SD_COUNTRY_NAME, SD_STATE_OR_PROVINCE_NAME, SD_LOCALITY_NAME, SD_ORGANIZATION_NAME)
        return details.subject()


class CP(Entity):
    """ Control Point """
    def __init__(self) -> None:
        super().__init__('CP')

    def generate_subject(self) -> x509.Name:
        details = Details(CP_COUNTRY_NAME, CP_STATE_OR_PROVINCE_NAME, CP_LOCALITY_NAME, CP_ORGANIZATION_NAME)
        return details.subject()


class UCA(Entity):
    """ UPnP Certification Authority """
    def __init__(self) -> None:
        super().__init__('UCA')
   
    def generate_subject(self) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, UCA_COMMON_NAME), 
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, UCA_ORGANIZATION_NAME)
        ])

class CA(Entity):
    """ UPnP Certification Authority """
    def __init__(self) -> None:
        super().__init__('CA')
        self.ca = True
   
    def generate_subject(self) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME), 
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION_NAME)
        ])

class FileHelper:
    """ Helper class for file operations. """

    @staticmethod
    def read_file(filepath: str, flags = 'r') -> str:
        """ Read file content and return it as a string. """
        if not os.path.exists(filepath):
            error("File '%s' does not exist." % filepath)
        with open(filepath, flags) as f:
            return f.read()
        
    @staticmethod
    def write_file(filepath: str, content: any, flags='w') -> None:
        """ Write content to a file. """
        with open(filepath, flags) as f:
            f.write(content)
            print("\tGenerated '%s'" % filepath)

    @staticmethod
    def write_json(filepath: str, content: dict) -> None:
        """ Write content to a file in JSON format. """
        FileHelper.write_file(filepath, json.dumps(content, indent=JSON_INDENT))


class CryptoHelper:
    """ Helper class for cryptographic operations. """
    PRIVATE_KEY_PEM = 'private_key.pem'
    PUBLIC_KEY_PEM  = 'public_key.pem'
    CERTIFICATE_PEM = 'certificate.pem'
    PADDING         = padding.PKCS1v15()
    ALGORITHM       = hashes.SHA256()
    PEM_ENCODING    = serialization.Encoding.PEM
    DER_ENCODING    = serialization.Encoding.DER
    PRIVATE_FORMAT  = serialization.PrivateFormat.PKCS8
    PUBLIC_FORMAT   = serialization.PublicFormat.SubjectPublicKeyInfo

    @staticmethod
    def private_key_to_bytes(key: PrivateKeyTypes, encoding: serialization.Encoding) -> bytes:
        """ Convert RSA key object to bytes. (PEM Format) """
        return key.private_bytes(encoding, CryptoHelper.PRIVATE_FORMAT, serialization.NoEncryption())

    @staticmethod
    def public_key_to_bytes(key: PublicKeyTypes, encoding: serialization.Encoding) -> bytes:
        """ Convert RSA key object to bytes. (PEM Format) """
        return key.public_bytes(encoding, CryptoHelper.PUBLIC_FORMAT)

    @staticmethod
    def generate_key_pair(directory: str) -> tuple[PrivateKeyTypes, PublicKeyTypes]:
        """ Generate RSA key pair, save them to files and return (private_key, public_key). """
        # Generate a new RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        # Serialize keys to PEM format
        private_key_pem = CryptoHelper.private_key_to_bytes(private_key, CryptoHelper.PEM_ENCODING)
        public_key_pem  = CryptoHelper.public_key_to_bytes(public_key, CryptoHelper.PEM_ENCODING)
        # Save the keys to files
        FileHelper.write_file("%s/%s" % (directory, CryptoHelper.PRIVATE_KEY_PEM), private_key_pem, 'wb')
        FileHelper.write_file("%s/%s" % (directory, CryptoHelper.PUBLIC_KEY_PEM),  public_key_pem,  'wb')
        return private_key, public_key

    @staticmethod
    def sign_data(data: bytes, private_key: PrivateKeyTypes) -> bytes:
        """ Sign data using RSA private key. """
        return private_key.sign(data, CryptoHelper.PADDING, CryptoHelper.ALGORITHM).hex()

    @staticmethod
    def issue_certificate(issuer: Entity, entity: Entity) -> x509.Certificate:
        """ 
        Generate a certificate for entity which contains the entity's public key.
        The certificate is signed by private_key.
        """
        try:
            print("\t%s signs %s's certificate.." % (issuer, entity))
            builder = CryptoHelper.get_cert_builer(entity.subject, issuer.subject, entity.public_key)
            if issuer.ca:  # CA is the signer
                builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            cert = builder.sign(issuer.private_key, CryptoHelper.ALGORITHM, default_backend())
            FileHelper.write_file("%s/%s" % (entity, CryptoHelper.CERTIFICATE_PEM), cert.public_bytes(CryptoHelper.PEM_ENCODING), 'wb')
            return cert
        except Exception as e:
            error("%s failed to issue Certificate for %s. %s" % (issuer, entity, str(e)))

    @staticmethod
    def verify_signature(name: str, data: bytes, signature: bytes, public_key: PublicKeyTypes, verbose: bool = True) -> bool:
        """ Verify the signature of data using RSA public key. """
        try:
            if verbose:
                print("\tVerifying '%s'.." % name, end='\t\t')
            public_key.verify(
                signature=signature,
                data=data,
                padding=CryptoHelper.PADDING,
                algorithm=CryptoHelper.ALGORITHM
            )
            if verbose:
                print("signature ok.")   # No exception means signature is valid.
            return True
        except InvalidSignature:
            if verbose:
                print("Signature verification failed.")
            return False
    
    @staticmethod
    def verify_certificate(entity: Entity, public_key: PublicKeyTypes) -> None:
        """ Verify the certificate using the public key. """
        try:
            print("\tVerifying %s's certificate.." % entity, end='\t')
            cert_file = '%s/%s' % (entity, CryptoHelper.CERTIFICATE_PEM)
            cert = FileHelper.read_file(cert_file, 'rb')
            cert_obj: x509.Certificate = x509.load_pem_x509_certificate(cert, default_backend())
            # Verify that read file is the expected certificate.
            if (cert_obj != entity.cert):
                print("Certificate verification failed - Certificate '%s' bytes mismatch." % cert_file)
                return
            # Verify that public key in the certificate is the same as the entity's public key.
            if (entity.public_key != entity.cert.public_key()):
                print("Certificate verification failed - %s's Public key mismatch." % entity)
                return
            # Verify the certificate signature with the given public_key
            if not CryptoHelper.verify_signature(str(entity), entity.cert.tbs_certificate_bytes, entity.cert.signature, public_key, verbose=False):
                print("Certificate verification failed - Signature verification failed.")
                return
    
            print("certificate ok.")
        except Exception as e:
            print("Failed: %s" % str(e))

    @staticmethod
    def get_cert_builer(subject: x509.Name, issuer: x509.Name, public_key: PublicKeyTypes) -> x509.CertificateBuilder:
        """ Generate a certificate builder. """
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.not_valid_before(datetime.datetime.today() - datetime.timedelta(days=1))
        builder = builder.not_valid_after(datetime.datetime.today() + datetime.timedelta(days=CERTIFICATE_VALIDITY_DAYS))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        return builder


class Doc:
    """ Common logics for DSD and SAD. """
    def __init__(self, doc_type: str, name: str, public_key: PublicKeyTypes, services: dict, **kwargs: dict):
        self._doc = {}
        self._doc['TYPE'] = doc_type
        self._doc['NAME'] = name
        self._doc['PK']   = CryptoHelper.public_key_to_bytes(public_key, CryptoHelper.DER_ENCODING).hex()
        for key, value in kwargs.items():
            self._doc[key] = value
        self._doc['SERVICES'] = services
        self._doc['SIG-VER-CON'] = '2-of-2'
        self._doc['SIGS'] = ['SIG-OWNER', 'SIG-UCA']

    @staticmethod
    def raw_doc(doc) -> bytes:
        """ Get the raw document content which can be signed. """
        return json.dumps(doc, separators=(',', ':')).encode('utf-8')

    def sign(self, sk_owner: PrivateKeyTypes, sk_uca: PrivateKeyTypes) -> dict:
        """ Sign the document using the secret keys. """
        json_doc = Doc.raw_doc(self._doc)  #  Sign unformatted JSON
        doc = self._doc.copy()
        doc['SIG-OWNER'] = CryptoHelper.sign_data(json_doc, sk_owner)
        doc['SIG-UCA']   = CryptoHelper.sign_data(json_doc, sk_uca)
        return doc

    def __setitem__(self, key, value):
        self._doc[key] = value

    @staticmethod
    def verify_document(name: str, entity: Entity, public_key_uca: PublicKeyTypes) -> None:
        """ Verify the signature of data using RSA public key. """
        try:
            print("[*] Verifying signatures for '%s':" % name)
            filepath = '%s/%s.json' % (entity, name.lower())
            data = json.loads(FileHelper.read_file(filepath))
            print("\tVerifying public key..", end='\t\t')
            public_key = bytes.fromhex(data['PK'])
            if (public_key != CryptoHelper.public_key_to_bytes(entity.public_key, CryptoHelper.DER_ENCODING)):
                print("Public key mismatch for '%s'." % name)
            else:
                print("public key ok.")
            sig_owner = data.pop('SIG-OWNER')
            sig_uca   = data.pop('SIG-UCA')
            json_doc = Doc.raw_doc(data)  # unformatted json
            _ = CryptoHelper.verify_signature('SIG-OWNER', json_doc, bytes.fromhex(sig_owner), entity.public_key)
            _ = CryptoHelper.verify_signature('SIG-UCA',   json_doc, bytes.fromhex(sig_uca),   public_key_uca)
        except Exception as e:
            print("[!] Unexpected error during document verification error for '%s': %s" % (name, str(e)))


class Device:
    """ UPnP Device Data """
    DEVICE_NODE  = 'device'
    SERVICE_NODE = 'service'

    def __init__(self, device_desc_path: str):
        try:
            self._desc: dict = xmltodict.parse(FileHelper.read_file(device_desc_path)) # Device Description Document content.
            print("[*] Initialized Device('%s')" % device_desc_path)
        except Exception as e:
            error("Device::__init__: Failed to parse '%s': %s. Is device description xml document provided?" % (device_desc_path, str(e)))

    def _get_node(self, node_name: str, recursive_dict: dict):
        for key, value in recursive_dict.items():
            if node_name == key:
                yield value
            elif isinstance(value, dict):
                yield from self._get_node(node_name, value)
    
    def get_node(self, node_name: str) -> dict:
        try:
            return next(self._get_node(node_name, self._desc))
        except StopIteration:
            error("Device::get_node: Failed to extract node '%s'. Is device description xml document provided?" % node_name)
    
    def desc_json(self) -> str:
        return json.dumps(self.get_node(Device.DEVICE_NODE), indent=JSON_INDENT)    # Export only device info without xml header.
    
    def desc_xml(self) -> str:
        return xmltodict.unparse(self._desc, pretty=True)  # Use full xml data
    
    def __str__(self) -> str:
        return self.desc_json()
    
    """
    https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf#page=52
    <service>
      <serviceType>urn:schemas-upnp-org:service:serviceType:v</serviceType>
      <serviceId>urn:upnp-org:serviceId:serviceID</serviceId>
      urn:upnp-org:serviceId:tvpicture1
      ...
    </service>
    """
    def service_list(self) -> dict:
        service_list = {}
        for service in self.get_node(Device.SERVICE_NODE):
            try:
                name = re.search(r'urn:upnp-org:serviceId:(\w+)', service['serviceId']).group(1)
                type = re.search(r'urn:schemas-upnp-org:service:(\w+):\d+', service['serviceType']).group(1)
                service_list[name] = type
            except Exception as e:
                error("Device::service_list: Failed to parse '%s'. Is device description xml document provided?" % str(service))
        return service_list
    
    # DSD (Device Specification Document) Components:
    # TYPE:         Type of of the participant - "SD" (Service Device).
    # PK:           Public Key of the SD.
    # HW:           Hardware description of the device (e.g., CPU, RAM, ROM, and network interfaces).
    # SW:           Software specification of the device (e.g., operating system and runtime environment).
    # SERVICES:     The list of services, represented as (name, type) pairs, that are provided by the SD.
    # SIG-OWNER:    The signature of owner, generated from the DSD contents using the secret key of the SD.
    # SIG-UCA:      The signature of the UCA, generated from the DSD contents using the secret key of the UCA.
    # SIG-VER-CON:  The verification condition of the DSD. The “CON” field value “2-of-2” means both signatures mentioned in the “SIGS” 
    #               field need to be verified to prove the authenticity of this document.
    # SIGS:         The signatures need to be verified to check the authenticity of this document.
    #
    def generate_dsd(self, uca: UCA, sd: SD) -> dict:
        """ Generate DSD (Device Specification Document)"""
        doc = Doc('SD', 'SD user-friendly name', sd.public_key, self.service_list(), 
                  HW='SD Hardware Description', SW='SD Software Description')  # Probaby not mandatory for simulation.
        FileHelper.write_json('%s/dsd.json' % sd, doc.sign(sk_owner=sd.private_key, sk_uca=uca.private_key))
    
    # SAD (Service Action Document) Components:
    # TYPE:         Type of of the participant - "CP" (Control Point).
    # PK:           Public Key of the CP.
    # SERVICES:     The list of services, represented as (name, type) pairs, that the CP will be authorized to use.
    # SIG-OWNER:    The signature of owner, generated from the SAD contents using the secret key of the SD.
    # SIG-UCA:      The signature of the UCA, generated from the SAD contents using the secret key of the UCA.
    # SIG-VER-CON:  The verification condition of the SAD. The “CON” field value “2-of-2” means both signatures mentioned in the “SIGS” 
    #               field need to be verified to prove the authenticity of this document.
    # SIGS:         The signatures need to be verified to check the authenticity of this document.
    def generate_sad(self, uca: UCA, cp: CP) -> None:
        """ Generate SAD (Service Action Document)"""
        doc = Doc('CP', 'CP user-friendly name', cp.public_key, self.service_list())
        FileHelper.write_json('%s/sad.json' % cp, doc.sign(sk_owner=cp.private_key, sk_uca=uca.private_key))


if __name__ == "__main__":
    print("~~~ Device Enrollment simulation ~~~")
    parser = argparse.ArgumentParser()
    parser.add_argument("devicedesc_xml", help="UPnP XML Description Document filepath.")
    device = Device(parser.parse_args().devicedesc_xml)
    ca  = CA()
    uca = UCA()
    uca.cert = CryptoHelper.issue_certificate(ca, uca)
    cp  = CP()
    cp.cert = CryptoHelper.issue_certificate(uca, cp)
    sd  = SD()
    sd.cert = CryptoHelper.issue_certificate(uca, sd)
    print("[*] Generating documents..")
    device.generate_sad(uca, cp)
    device.generate_dsd(uca, sd)
    # Verify signatures
    Doc.verify_document('SAD', cp, uca.public_key)
    Doc.verify_document('DSD', sd, uca.public_key)
    print("[*] Verifying certificates..")
    CryptoHelper.verify_certificate(uca, ca.public_key)
    CryptoHelper.verify_certificate(cp, uca.public_key)
    CryptoHelper.verify_certificate(sd, uca.public_key)
    print("[*] Done.")

