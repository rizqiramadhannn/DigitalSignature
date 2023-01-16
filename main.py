#library untuk web
from flask import Flask, render_template, request, send_file 
import os
import shutil
import datetime

#utils for the digital signature (keys / certificates)
import OpenSSL
import os
import time
from PDFNetPython3.PDFNetPython import *
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12

#utils for pdf signing / manipulation
from PIL import Image

app = Flask('app')

@app.route('/')
def home():
  return render_template("index.html")

def createKeyPair_RSA(type, bits):
    """
    Create a public/private key pair
    Arguments: Type - Key Type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key (1024 or 2048 or 4096)
    Returns: The public/private key pair in a PKey object
    """
    key_time = time.time()
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(type, bits)
    print("Waktu proses key generation      : %s second" % (time.time() - key_time))
    return pkey

def create_self_signed_cert(pKey, name):
    """Create a self signed certificate. This certificate will not require to be signed by a Certificate Authority."""
    # Create a self signed certificate
    cert = OpenSSL.crypto.X509()
    # Common Name (e.g. server FQDN or Your Name)
    cert.get_subject().CN = name
    # Serial Number
    cert.set_serial_number(int(time.time() * 10))
    # Not Before
    cert.gmtime_adj_notBefore(0)  # Not before
    # Not After (Expire after 1 year)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    # Identify issue
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'sha256')  # or cert.sign(pKey, 'sha256')
    return cert

def load(name, algo):
    """Generate the certificate"""
    summary = {}
    summary['OpenSSL Version'] = OpenSSL.__version__
    # Generating a Private Key...
    if algo == "RSA":
        key = createKeyPair_RSA(OpenSSL.crypto.TYPE_RSA, 1024)
    elif algo == "ECDSA":
        key_time = time.time()
        key = ec.generate_private_key(ec.SECP384R1())
        print("Waktu proses key generation      : %s second" % (time.time() - key_time))
    else:
        key = createKeyPair_RSA(OpenSSL.crypto.TYPE_DSA, 1024)
    # PEM encoded
    if algo == "ECDSA":
        with open('.\static\private_key.pem', 'wb') as pk:
            pk_str = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            pk.write(pk_str)
            summary['Private Key'] = pk_str
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        with open(".\static\certificate.cer", "wb") as f:
            cer_str = cert.public_bytes(serialization.Encoding.PEM)
            f.write(cer_str)
            summary['Self Signed Certificate'] = cer_str
        public_key = key.public_key()
        with open('.\static\public_key.pem', 'wb') as pub_key:
            pub_key_str = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            pub_key.write(pub_key_str)
            summary['Public Key'] = pub_key_str
        p12 = pkcs12.serialize_key_and_certificates(
            b"friendlyname", key, cert, None, serialization.NoEncryption()
        )
        open('.\static\container.pfx', 'wb').write(p12)
    else:
        with open('.\static\private_key.pem', 'wb') as pk:
            pk_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
            pk.write(pk_str)
            summary['Private Key'] = pk_str
        # Done - Generating a private key...
        # Generating a self-signed client certification...
        cert = create_self_signed_cert(pKey=key, name=name)
        with open('.\static\certificate.cer', 'wb') as cer:
            cer_str = OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, cert)
            cer.write(cer_str)
            summary['Self Signed Certificate'] = cer_str
        # Done - Generating a self-signed client certification...
        # Generating the public key...
        with open('.\static\public_key.pem', 'wb') as pub_key:
            pub_key_str = OpenSSL.crypto.dump_publickey(
                OpenSSL.crypto.FILETYPE_PEM, cert.get_pubkey())
            #print("Public key = ",pub_key_str)
            pub_key.write(pub_key_str)
            summary['Public Key'] = pub_key_str
        # Done - Generating the public key...
        # Take a private key and a certificate and combine them into a PKCS12 file.
        # Generating a container file of the private key and the certificate...
        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(key)
        p12.set_certificate(cert)
        open('.\static\container.pfx', 'wb').write(p12.export())
    # You may convert a PKSC12 file (.pfx) to a PEM format
    # Done - Generating a container file of the private key and the certificate...
    # To Display A Summary
    print("## Initialization Summary ##################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("############################################################################")
    return True

def sign_file(input_file: str, signatureID: str, x1: int, 
            y1: int, x2: int, y2: int, pages: Tuple = None, output_file: str = None, reason:str = None
              ):
    """Sign a PDF file"""
    # An output file is automatically generated with the word signed added at its end
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
    # Initialize the library
    PDFNet.Initialize("demo:1668463720500:7ab997d50300000000920d5913c61681297d78eb39c9ece75410ae7bea")
    doc = PDFDoc(input_file)
    # Create a signature field
    sigField = SignatureWidget.Create(doc, Rect(
        x1, y1, x2, y2), signatureID)
    # Iterate throughout document pages
    for page in range(1, (doc.GetPageCount() + 1)):
        # If required for specific pages
        if pages:
            if str(page) not in pages:
                continue
        pg = doc.GetPage(page)
        # Create a signature text field and push it on the page
        pg.AnnotPushBack(sigField)
    # Signature image
    sign_filename = os.path.dirname(
        os.path.abspath(__file__)) + ".\signature.png"
    # Self signed certificate
    pk_filename = os.path.dirname(
        os.path.abspath(__file__)) + "\static\container.pfx"
    # Retrieve the signature field.
    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)
    # Add appearance to the signature field.
    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(
        approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)
    # Prepare the signature and signature handler for signing.
    approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
    # The signing will be done during the following incremental save operation.
    sign_time = time.time()
    doc.Save(output_file, SDFDoc.e_incremental)
    print("Waktu proses sign pdf      : %s second" % (time.time() - sign_time))
    # Develop a Process Summary
    summary = {
        "Input File": input_file, "Signature ID": signatureID, 
        "Output File": output_file, "Signature File": sign_filename, 
        "Certificate File": pk_filename
    }
    # Printing Summary
    print("## Summary ########################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("###################################################################")
    os.remove("signature.png")
    os.remove(".\static\source.pdf")
    fn = os.path.basename(input_file)
    # open read and write the file into the server
    open(fn, 'wb')
    return fn

@app.route('/sign', methods=["POST"])
def sign():
  if request.method == "POST":
    
    name = request.form['name']
    email = request.form['email']
    algorithm = request.form['algorithm']
    y_compensator = round(float(request.form['ycom']))
    x1 = int(request.form['x1'])
    y1 = y_compensator - int(request.form['y1'])
    x2 = int(request.form['x2'])
    y2 = y_compensator - int(request.form['y2'])
    region = request.form['region']
    page = request.form['page']
    data = request.files.get('file', None)
    img = request.files.get('sig', None)
    #args = parse_args()
    # check if the file has been uploaded
    if img.filename:
        # strip the leading path from the file name
        fn = os.path.basename(img.filename)
    # open read and write the file into the server
        open(fn, 'wb').write(img.read())
        os.rename(img.filename, "signature.png")

    # check if the file has been uploaded
    if data.filename:
        # strip the leading path from the file name
        fn = os.path.basename(data.filename)
    # open read and write the file into the server
        open(fn, 'wb').write(data.read())
        os.rename(data.filename, "source.pdf")
        shutil.move(".\source.pdf", ".\static\source.pdf")
    
    load(name, algorithm)
    data = request.files.get('file', None)
    if data.filename.rsplit('.', 1)[1].lower() == "pdf":
        sign_file(input_file=".\static\source.pdf", signatureID=name, x1=x1, x2=x2, y1=y1, y2=y2, pages=page, output_file=".\static\\result.pdf")
        r = send_file(".\static\\result.pdf", mimetype="application/pdf", as_attachment=False)
        os.remove("source.pdf")
        return r
    else: 
      return render_template("error.html", e="Wrong File Type, not a PDF", c="PDF File Error")
app.run(host='0.0.0.0', port=8080, debug=True)
