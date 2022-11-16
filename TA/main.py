#library untuk web
from flask import Flask, render_template, request, send_file 
import os
import shutil
import tempfile
import datetime

#library untuk log sistem
import traceback
import sys 

import base64

#utils for the digital signature (keys / certificates)
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12

#utils for pdf signing / manipulation
from endesive.pdf import cms
from PIL import Image, ImageOps

app = Flask('app')

# # def getHankoImage(text, shape, style, font, origin=None, rotation=0):
# #   site = "https://www.hankogenerator.com"
# #   url = site + "/getimage/"

# #   s = requests.Session() 
# #   r = s.get(site).text
# #   soup = BeautifulSoup(r, 'html.parser')

# #   token = soup.find(attrs={"name": "csrfmiddlewaretoken"})['value']

# #   headers = {"referer": "https://www.hankogenerator.com/", "content-type":"application/x-www-form-urlencoded"}

# #   #input parameters: text <kanji/hiragana/katakana chars>, shape <round/square>, style & font => check website for types
  
# #   data = {"Text":text,"size":"0.83","shape":shape,"style":style,"font": font, "csrfmiddlewaretoken":token}

# #   p = s.post(url, data=data, headers=headers)

# #   if origin != None: 
# #     if p.status_code == 200: 
# #       return p.text
# #     else: 
# #       return "Error: " + p.text
# #   else: 
# #     if p.status_code == 200: 
# #       _fq, imagepath = tempfile.mkstemp(".png")
# #       imgdata = base64.b64decode(p.text)
# #       with open(imagepath, 'wb') as f:
# #           f.write(imgdata)
# #       img = Image.open(imagepath).rotate(rotation+180) #endesive rotation needs compensation
# #       if shape == "square":
# #         side = img.size[0]
# #         ImageOps.expand(img, border=side//20, fill="red").save(imagepath) #borders for square seals need enhancement
# #       else:
# #         img.save(imagepath)
# #       img.close()
# #       return [imagepath, _fq]
# #     else:
# #       app.logger.error("Issue with website scraping: " + p.text)
# #       return ["Message: Dependency Error [Check Console]", p.text]

# #def signPDF(docdata, page, email, name, shape, style, font, region, x1,y1,x2,y2, rotation):
# def signPDF(docdata, page, email, name, region, x1,y1,x2,y2):
#   try:
#     # res = getHankoImage(name, shape, style, font, rotation=rotation)
#     _fq, imagepath = tempfile.mkstemp(".png")
#     imgdata = base64.b64decode("test")
#     with open(imagepath, 'wb') as f:
#         f.write(imgdata)
#     img = Image.open(imagepath)
#     img.save(imagepath)
#     img.close()
#     res = [imagepath, _fq]
#     _fr, fname = tempfile.mkstemp(".pdf")

#     one_day = datetime.timedelta(1, 0, 0)
#     private_key = rsa.generate_private_key(
#       public_exponent=65537,
#       key_size=2048,
#       backend=default_backend()
#     )
#     public_key = private_key.public_key()
#     builder = x509.CertificateBuilder()
#     builder = builder.subject_name(x509.Name([
#       x509.NameAttribute(NameOID.COMMON_NAME, name),
#     ]))
#     builder = builder.issuer_name(x509.Name([
#       x509.NameAttribute(NameOID.COMMON_NAME, u'inkantan'),
#     ]))
#     builder = builder.not_valid_before(datetime.datetime.today() - one_day)
#     builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 365))
#     builder = builder.serial_number(x509.random_serial_number())
#     builder = builder.public_key(public_key)
#     builder = builder.add_extension(
#       x509.SubjectAlternativeName(
#           [x509.DNSName("@inkantan")]
#       ),
#       critical=False
#     )
#     builder = builder.add_extension(
#       x509.BasicConstraints(ca=False, path_length=None), critical=True,
#     )
#     certificate = builder.sign(
#       private_key=private_key, algorithm=hashes.SHA256(),
#       backend=default_backend()
#     )
#     p12 = pkcs12.serialize_key_and_certificates(b'test', private_key, certificate, [certificate], serialization.BestAvailableEncryption(b'1234'))
#     y = pkcs12.load_key_and_certificates(p12, b'1234', default_backend())

#     date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
#     date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
#     tspurl = "http://public-qlts.certum.pl/qts-17"
#     dct = {
#         "aligned": 0,
#         "sigflags": 1,
#         "sigflagsft": 132,
#         "sigpage": int(page)-1,
#         "sigbutton": True,
#         "sigfield": "Signature1",
#         "sigandcertify": True,
#         "signaturebox": (max(x1,x2),(max(y1,y2)),min(x1,x2),min(y1,y2)), 
#         "signature_img": res[0],
#         "contact": email,
#         "location": region,
#         "signingdate": date,
#         "reason": "To execute/formalize/affirm the contract", 
#         "password": "1234",
#     }

#     with open(fname, 'wb') as fx: 
#       fx.write(docdata)

#     datau = open(fname, "rb").read()
#     try:
#       datas = cms.sign(datau, dct, y[0], y[1], y[2], "sha256", timestampurl=tspurl)
#     except Exception as x:
#       return errHandler(x, [res[0], fname], [res[1], _fr])
      
#     with open(fname, "wb") as fp:
#         fp.write(datau)
#         fp.write(datas)
#     os.close(res[1])
#     os.remove(res[0])
#     os.close(_fr)
#     return fname
#   except Exception as e:
#     return errHandler(e, [res[0], fname], [res[1], _fr])

# def errHandler(e, path, descriptor):
#   #clean up memory
#   for i in descriptor:
#     os.close(i)
#   for j in path:
#     os.remove(j)
#   #log
#   app.logger.error(e)
#   app.logger.info(traceback.format_exc())
#   exc_type, exc_value, exc_traceback = sys.exc_info()
#   return ["Error Message: " + str(exc_value), str(traceback.format_exc())]

# @app.route('/')
# def home():
#   return render_template("index.html")

# # @app.route('/test', methods=["POST"])
# # def test():
# #   content = request.json
# #   return getHankoImage(content['name'], content['shape'], content['style'], content['font'], "self")

# @app.route('/sign', methods=["POST"])
# def sign():
#   if request.method == "POST":
    
#     name = request.form['name']
#     email = request.form['email']
#     y_compensator = round(float(request.form['ycom']))
#     x1 = int(request.form['x1'])
#     y1 = y_compensator - int(request.form['y1'])
#     x2 = int(request.form['x2'])
#     y2 = y_compensator - int(request.form['y2'])
#     # shape = request.form['shape']
#     # style = request.form['style']
#     # font = request.form['font']
#     region = request.form['region']
#     page = request.form['page']
#     # if request.form['rotation'] in ["", None] or request.form['shape'] != "round": 
#     #   rotation = 0
#     # else:
#     #   rotation = int(request.form['rotation'])
#     data = request.files.get('file', None)
    
#     if data.filename.rsplit('.', 1)[1].lower() == "pdf":
#       #api_response = signPDF(data.read(), page, email, name, shape, style, font, region, x1, y1, x2, y2, rotation)
#       api_response = signPDF(data.read(), page, email, name, region, x1, y1, x2, y2)
#       if type(api_response) == list:
#         return render_template("error.html", e=api_response[0], c=api_response[1])
#       elif api_response == None:
#         return render_template("error.html", e="Nonetype: Script Error", c="Check server logs")
#       else:
#         r = send_file(api_response, mimetype="application/pdf", as_attachment=False)
#         os.remove(api_response)
#         return r
#     else: 
#       return render_template("error.html", e="Wrong File Type, not a PDF", c="PDF File Error")

# test
# Import Libraries
import OpenSSL
import os
import time
import argparse
from PDFNetPython3.PDFNetPython import *
from typing import Tuple

@app.route('/')
def home():
  return render_template("index.html")

def createKeyPair(type, bits):
    """
    Create a public/private key pair
    Arguments: Type - Key Type, must be one of TYPE_RSA and TYPE_DSA
               bits - Number of bits to use in the key (1024 or 2048 or 4096)
    Returns: The public/private key pair in a PKey object
    """
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(type, bits)
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
    # Not After (Expire after 1 years)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    # Identify issue
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'md5')  # or cert.sign(pKey, 'sha256')
    return cert
def load(name):
    """Generate the certificate"""
    summary = {}
    summary['OpenSSL Version'] = OpenSSL.__version__
    # Generating a Private Key...
    key = createKeyPair(OpenSSL.crypto.TYPE_RSA, 1024)
    # PEM encoded
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
            y1: int, x2: int, y2: int, pages: Tuple = None, output_file: str = None
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
    doc.Save(output_file, SDFDoc.e_incremental)
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
def sign_folder(**kwargs):
    """Sign all PDF Files within a specified path"""
    input_folder = kwargs.get('input_folder')
    signatureID = kwargs.get('signatureID')
    pages = kwargs.get('pages')
    x_coordinate = int(kwargs.get('x_coordinate'))
    y_coordinate = int(kwargs.get('y_coordinate'))
    # Run in recursive mode
    recursive = kwargs.get('recursive')
    # Loop though the files within the input folder.
    for foldername, dirs, filenames in os.walk(input_folder):
        for filename in filenames:
            # Check if pdf file
            if not filename.endswith('.pdf'):
                continue
            # PDF File found
            inp_pdf_file = os.path.join(foldername, filename)
            print("Processing file =", inp_pdf_file)
            # Compress Existing file
            sign_file(input_file=inp_pdf_file, signatureID=signatureID, x_coordinate=x_coordinate,
                      y_coordinate=y_coordinate, pages=pages, output_file=None)
        if not recursive:
            break
def is_valid_path(path):
    """Validates the path inputted and checks whether it is a file path or a folder path"""
    if not path:
        raise ValueError(f"Invalid Path")
    if os.path.isfile(path):
        return path
    elif os.path.isdir(path):
        return path
    else:
        raise ValueError(f"Invalid Path {path}")
def parse_args():
    """Get user command line parameters"""
    parser = argparse.ArgumentParser(description="Available Options")
    parser.add_argument('-l', '--load', dest='load', action="store_true",
                        help="Load the required configurations and create the certificate")
    parser.add_argument('-i', '--input_path', dest='input_path', type=is_valid_path,
                        help="Enter the path of the file or the folder to process")
    parser.add_argument('-s', '--signatureID', dest='signatureID',
                        type=str, help="Enter the ID of the signature")
    parser.add_argument('-p', '--pages', dest='pages', type=tuple,
                        help="Enter the pages to consider e.g.: [1,3]")
    parser.add_argument('-x', '--x_coordinate', dest='x_coordinate',
                        type=int, help="Enter the x coordinate.")
    parser.add_argument('-y', '--y_coordinate', dest='y_coordinate',
                        type=int, help="Enter the y coordinate.")
    path = parser.parse_known_args()[0].input_path
    if path and os.path.isfile(path):
        parser.add_argument('-o', '--output_file', dest='output_file',
                            type=str, help="Enter a valid output file")
    if path and os.path.isdir(path):
        parser.add_argument('-r', '--recursive', dest='recursive', default=False, type=lambda x: (
            str(x).lower() in ['true', '1', 'yes']), help="Process Recursively or Non-Recursively")
    args = vars(parser.parse_args())
    # To Display The Command Line Arguments
    print("## Command Arguments #################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in args.items()))
    print("######################################################################")
    return args
@app.route('/sign', methods=["POST"])
def sign():
  if request.method == "POST":
    
    name = request.form['name']
    email = request.form['email']
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
    
    load(name)
    data = request.files.get('file', None)
    if data.filename.rsplit('.', 1)[1].lower() == "pdf":
        sign_file(input_file=".\static\source.pdf", signatureID=name, x1=x1, x2=x2, y1=y1, y2=y2, pages=page, output_file=".\static\\result.pdf")
        r = send_file(".\static\\result.pdf", mimetype="application/pdf", as_attachment=False)
        return r
    else: 
      return render_template("error.html", e="Wrong File Type, not a PDF", c="PDF File Error")
app.run(host='0.0.0.0', port=8080, debug=True)
