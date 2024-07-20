# Simulation

This folder contains simulation scripts to demonstrate SUPnP capabilities. The SUPnP Protocol Scheme is presented in the paper [Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973). 

The use of the paper and the implementation of some parts in it are only for educational and self learning purposes.

<br />

## Requirements

* Python 3
* `pip install -r requirements.txt`

<br />

## Device Enrollment

The `device_enrollment.py` script is responsible for generating the required artifacts which are requried by the later phases of the SUPnP. It's a simulating the part "A. Device Enrollment" of the SUPnP proposed scheme which is presented in the paper [Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973).

Given a device description xml document file, the script will generate the following artifcats:

* $SK{ca}$ - A common CA's private key. PEM format.
* $PK{ca}$ - A common CA's public key. PEM format.
* $Cert_{uca}$ - UCA (UPnP Certification Authority) certificate signed by CA's public key. PEM format.
* $SK_{uca}$ - UCA's private key. PEM format.
* $PK_{uca}$ - UCA's public key. PEM format.
* $Cert_{cp}$ - CP (Control Point) certificate, which contains CP's public key, and signed by UCA's private key. PEM format.
* $SK_{cp}$ - CP's private key. PEM format.
* $PK_{cp}$ - CP's public key. PEM format.
* $Cert_{sd}$ - SD (Service Device) certificate, which contains SD's public key, and signed by UCA's private key. PEM format.
* $SK_{sd}$ - SD's private key. PEM format.
* $PK_{sd}$ - SD's public key. PEM format.
* $DSD$ (Device Specification Document). JSON format. Signed by SD & UCA.
* $SAD$ (Service Action Document). JSON format. Signed by CP & UCA.

<br/>

The following artifacts should be stored on the SD: $PK_{ca}$, $Cert_{uca}$, $Cert_{sd}$, $SK_{sd}$, $PK_{sd}$ and $DSD$.

The following artifacts should be stored on the CP: $PK_{ca}$, $Cert_{uca}$, $Cert_{cp}$, $SK_{cp}$, $PK_{cp}$ and $SAD$.

Note that in the simulation scenraio the UCA is reused, but it can be different among devices. The root of trust is a CA which signs the different UCA entities.

<br/> 

### DSD (Device Specification Document) Components

The following DSD structure is presented by the paper in the paper [Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973).

* `TYPE` - Type of of the participant - "SD" (Service Device).
* `PK` - Public Key of the SD.
* `HW` - Hardware description of the device (e.g., CPU, RAM, ROM, and network interfaces).
* `SW` - Software specification of the device (e.g., operating system and runtime environment).
* `SERVICES` - The list of services, represented as (name, type) pairs, that are provided by the SD.
* `SIG-OWNER` - The signature of owner, generated from the DSD contents using the secret key of the SD.
* `SIG-UCA` - The signature of the UCA, generated from the DSD contents using the secret key of the UCA.
* `SIG-VER-CON` - The verification condition of the DSD. The “CON” field value “2-of-2” means both signatures mentioned in the “SIGS” field need to be verified to prove the authenticity of this document.
* `SIGS` - The signatures need to be verified to check the authenticity of this document.

<br/> 

### SAD (Service Action Document) Components

The following SAD structure is presented by the paper in the paper [Kayas, G., Hossain, M., Payton, J., & Islam, S. R. (2021). SUPnP: Secure Access and Service Registration for UPnP-Enabled Internet of Things. IEEE Internet of Things Journal, 8(14), 11561-11580](https://ieeexplore.ieee.org/document/9352973).


* `TYPE` - Type of of the participant - "CP" (Control Point).
* `PK` - Public Key of the CP.
* `SERVICES` - The list of services, represented as (name, type) pairs, that the CP will be authorized to use.
* `SIG-OWNER` - The signature of owner, generated from the SAD contents using the secret key of the SD.
* `SIG-UCA` - The signature of the UCA, generated from the SAD contents using the secret key of the UCA.
* `SIG-VER-CON` - The verification condition of the SAD. The “CON” field value “2-of-2” means both signatures mentioned in the “SIGS” field need to be verified to prove the authenticity of this document.
* `SIGS` - The signatures need to be verified to check the authenticity of this document.

<br/>

### Usage example

```sh
./venv/bin/python3 ./device_enrollment.py ../upnp/sample/web/tvdevicedesc.xml

~~~ Device Enrollment simulation ~~~
[*] Initialized Device('../upnp/sample/web/tvdevicedesc.xml')
[*] Initializing CA..
        Generated 'CA/private_key.pem'
        Generated 'CA/public_key.pem'
[*] Initializing UCA..
        Generated 'UCA/private_key.pem'
        Generated 'UCA/public_key.pem'
        CA signs UCA's certificate..
        Generated 'UCA/certificate.pem'
[*] Initializing CP..
        Generated 'CP/private_key.pem'
        Generated 'CP/public_key.pem'
        UCA signs CP's certificate..
        Generated 'CP/certificate.pem'
[*] Initializing SD..
        Generated 'SD/private_key.pem'
        Generated 'SD/public_key.pem'
        UCA signs SD's certificate..
        Generated 'SD/certificate.pem'
[*] Generating documents..
        Generated 'CP/sad.json'
        Generated 'SD/dsd.json'
[*] Verifying signatures for 'SAD':
        Verifying public key..          public key ok.
        Verifying 'SIG-OWNER'..         signature ok.
        Verifying 'SIG-UCA'..           signature ok.
[*] Verifying signatures for 'DSD':
        Verifying public key..          public key ok.
        Verifying 'SIG-OWNER'..         signature ok.
        Verifying 'SIG-UCA'..           signature ok.
[*] Verifying certificates..
        Verifying UCA's certificate..   certificate ok.
        Verifying CP's certificate..    certificate ok.
        Verifying SD's certificate..    certificate ok.
[*] Done.


tree CA UCA CP SD

CA
├── private_key.pem
└── public_key.pem
UCA
├── certificate.pem
├── private_key.pem
└── public_key.pem
CP
├── certificate.pem
├── private_key.pem
├── public_key.pem
└── sad.json
SD
├── certificate.pem
├── dsd.json
├── private_key.pem
└── public_key.pem

4 directories, 13 files

```
