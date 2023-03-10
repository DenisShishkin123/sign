# Import Libraries
import OpenSSL
import os
import time
import argparse
from PDFNetPython3.PDFNetPython import *
from typing import Tuple



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


def create_self_signed_cert(pKey):
    """Create a self signed certificate. This certificate will not require to be signed by a Certificate Authority."""
    # Create a self signed certificate
    cert = OpenSSL.crypto.X509()
    # Common Name (e.g. server FQDN or Your Name)
    cert.get_subject().CN = "BASSEM MARJI"
    # Serial Number
    cert.set_serial_number(int(time.time() * 10))
    # Not Before
    cert.gmtime_adj_notBefore(0)  # Not before
    # Not After (Expire after 10 years)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    # Identify issue
    cert.set_issuer((cert.get_subject()))
    cert.set_pubkey(pKey)
    cert.sign(pKey, 'md5')  # or cert.sign(pKey, 'sha256')
    return cert


def load():
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
    cert = create_self_signed_cert(pKey=key)
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



#  python sign.py -i ".\static\Letter of confirmation.pdf" -s "BM" -x 330 -y 280
#  python sign.py -i ".\static\Letter of confirmation.pdf" -s "BM" -x 150 -y 200



# подписание документа
def sign_file___old(input_file: str, signatureID: str,
              x_coordinate: int, y_coordinate: int,
              pages: Tuple = None, output_file: str = None

              ):
    """Sign a PDF file"""
    """Подпишите PDF-файл"""

#########################################################################################################
# переменные
    # Выходной файл автоматически генерируется со словом signed, добавленным в его конце
    # An output file is automatically generated with the word signed added at its end
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"

    # ЭП - Изображение Факсимиле
    # Signature image
    sign_filename = os.path.dirname(
        # os.path.abspath(__file__)) + "\static\signature.jpg"
        os.path.abspath(__file__)) + "\static\signature.png"

    # ЭП - сертификат
    # Self signed certificate
    pk_filename = os.path.dirname(
        # os.path.abspath(__file__)) + "\static\container.pfx"  # TODO container.pfx
        os.path.abspath(__file__)) + "\static\TESTcrl8080.pfx"  # TODO container.pfx

    password = "123"

#########################################################################################################
# Инициализировать библиотеку
    # Инициализировать библиотеку
    # Initialize the library
    LicenseKey = "demo:1678358255416:7d068c52030000000092d70fd9a3ccde4c73f71626a4933548b64e6e26"
    PDFNet.Initialize(LicenseKey)
    doc = PDFDoc(input_file)

#########################################################################################################

    # Создайте поле подписи
    # Create a signature field
    sigField = SignatureWidget.Create(doc, Rect(
        x_coordinate, y_coordinate, x_coordinate+100, y_coordinate+50), signatureID)  # TODO x_coordinate+100, y_coordinate+50


    # Повторять по страницам документа
    # Iterate throughout document pages
    for page in range(1, (doc.GetPageCount() + 1)):

        # Если требуется для определенных страниц
        # If required for specific pages
        if pages:
            if str(page) not in pages:
                continue
        pg = doc.GetPage(page)

        # Создайте текстовое поле подписи и разместите его на странице
        # Create a signature text field and push it on the page
        pg.AnnotPushBack(sigField)


    # Извлеките поле подписи.
    # Retrieve the signature field.
    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)

    # Добавьте внешний вид в поле подписи.
    # Add appearance to the signature field.
    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(
        approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)

    # Подготовьте подпись и обработчик подписи к подписанию.
    # Prepare the signature and signature handler for signing.
    # approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
    approval_signature_digsig_field.SignOnNextSave(pk_filename, password)

    # Подписание будет выполнено во время следующей операции инкрементного сохранения.
    # The signing will be done during the following incremental save operation.
    doc.Save(output_file, SDFDoc.e_incremental)

#########################################################################################################
#вывод
    # Разработайте краткое описание процесса
    # Develop a Process Summary
    summary = {
        "Input File": input_file, "Signature ID": signatureID, 
        "Output File": output_file, "Signature File": sign_filename, 
        "Certificate File": pk_filename
    }
    # Краткое описание печати
    # Printing Summary
    print("## Summary ########################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("###################################################################")
    return True

"""
входные данные:
+++++++++++++++++++++++++++++++++
- документ/папка
* страницы
* координаты подписи
* выходной документ

---------------------------------
- подписант 
- пароль password
* ЭП - сертификат pk_filename
* ЭП - факсимиле  sign_filename
"""

#  python sign.py -i ".\static\Letter of confirmation.pdf" -s "BM" -x 150 -y 200 -w "123" -k ".\static\TESTcrl8080.pfx" -f ".\static\signature.png"

# подписание документа
def sign_file(input_file: str, signatureID: str,
              x_coordinate: int, y_coordinate: int,
              pages: Tuple = None, output_file: str = None,

              pk_filename: str = None, sign_filename: str = None,
              password: str = None
              ):
    """Sign a PDF file"""
    """Подпишите PDF-файл"""

#########################################################################################################
# переменные

    if password == None: password = "123"

    # ЭП - Изображение Факсимиле
    # Signature image
    if sign_filename == None:
        sign_filename = os.path.dirname(os.path.abspath(__file__)) + "\static\signature.jpg"
    else: sign_filename = os.path.dirname(os.path.abspath(__file__)) + sign_filename

    # ЭП - сертификат
    # Self signed certificate
    if pk_filename == None:
        pk_filename = os.path.dirname(os.path.abspath(__file__)) + "\static\TESTcrl8080.pfx"
    else: pk_filename = os.path.dirname(os.path.abspath(__file__)) + pk_filename

    # Выходной файл автоматически генерируется со словом signed, добавленным в его конце
    # An output file is automatically generated with the word signed added at its end
    if not output_file:
        output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"

#########################################################################################################
# Инициализировать библиотеку
    # Инициализировать библиотеку
    # Initialize the library
    LicenseKey = "demo:1678358255416:7d068c52030000000092d70fd9a3ccde4c73f71626a4933548b64e6e26"
    PDFNet.Initialize(LicenseKey)
    doc = PDFDoc(input_file)

#########################################################################################################

    # Создайте поле подписи
    # Create a signature field
    sigField = SignatureWidget.Create(doc, Rect(
        x_coordinate, y_coordinate, x_coordinate+100, y_coordinate+50), signatureID)  # TODO x_coordinate+100, y_coordinate+50


    # Повторять по страницам документа
    # Iterate throughout document pages
    for page in range(1, (doc.GetPageCount() + 1)):

        # Если требуется для определенных страниц
        # If required for specific pages
        if pages:
            if str(page) not in pages:
                continue
        pg = doc.GetPage(page)

        # Создайте текстовое поле подписи и разместите его на странице
        # Create a signature text field and push it on the page
        pg.AnnotPushBack(sigField)


    # Извлеките поле подписи.
    # Retrieve the signature field.
    approval_field = doc.GetField(signatureID)
    approval_signature_digsig_field = DigitalSignatureField(approval_field)

    # Добавьте внешний вид в поле подписи.
    # Add appearance to the signature field.
    img = Image.Create(doc.GetSDFDoc(), sign_filename)
    found_approval_signature_widget = SignatureWidget(
        approval_field.GetSDFObj())
    found_approval_signature_widget.CreateSignatureAppearance(img)

    # Подготовьте подпись и обработчик подписи к подписанию.
    # Prepare the signature and signature handler for signing.
    # approval_signature_digsig_field.SignOnNextSave(pk_filename, '')
    approval_signature_digsig_field.SignOnNextSave(pk_filename, password)

    # Подписание будет выполнено во время следующей операции инкрементного сохранения.
    # The signing will be done during the following incremental save operation.
    doc.Save(output_file, SDFDoc.e_incremental)

#########################################################################################################
#вывод
    # Разработайте краткое описание процесса
    # Develop a Process Summary
    summary = {
        "Input File": input_file, "Signature ID": signatureID,
        "Output File": output_file, "Signature File": sign_filename,
        "Certificate File": pk_filename
    }
    # Краткое описание печати
    # Printing Summary
    print("## Summary ########################################################")
    print("\n".join("{}:{}".format(i, j) for i, j in summary.items()))
    print("###################################################################")
    return True


# python sign.py -i ".\static\pdf" -s "BM" -x 150 -y 200
# python sign.py -i ".\static\pdf" -s "BM" -x 150 -y 200 -w "123" -k ".\static\TESTcrl8080.pfx" -f ".\static\signature.png"

# подписание нескольких документов
def sign_folder(**kwargs):
    """Sign all PDF Files within a specified path"""
    input_folder = kwargs.get('input_folder')
    signatureID = kwargs.get('signatureID')
    pages = kwargs.get('pages')
    x_coordinate = int(kwargs.get('x_coordinate'))
    y_coordinate = int(kwargs.get('y_coordinate'))
    # Run in recursive mode
    recursive = kwargs.get('recursive')

    password = kwargs.get('password')
    pk_filename = kwargs.get('pk_filename')
    sign_filename = kwargs.get('sign_filename')
    # password=password, pk_filename=pk_filename, sign_filename=sign_filename,

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
            sign_file(
                password=password, pk_filename=pk_filename, sign_filename=sign_filename,
                      input_file=inp_pdf_file, signatureID=signatureID, x_coordinate=x_coordinate,
                      y_coordinate=y_coordinate, pages=pages, output_file=None)
        if not recursive:
            break




# код для разбора аргументов командной строки:

# Проверяет введенный путь и проверяет, является ли это путем к файлу или к папке
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

# Получение параметров командной строки пользователя
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


    parser.add_argument('-w', '--password', dest='password',
                        type=str, help="password.")

    parser.add_argument('-k', '--pk_filename', dest='pk_filename',
                        type=is_valid_path, help="pk_filename")
    parser.add_argument('-f', '--facsimile', dest='sign_filename',
                        type=is_valid_path, help="facsimile - sign_filename")


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

'''
--load или -l: Инициализируйте параметры конфигурации, создав самозаверяющий сертификат. Этот шаг следует выполнять один раз или по мере необходимости.
--input_path или -i: используется для ввода пути к файлу или папке для обработки, этот параметр связан с is_valid_path()ранее определенной функцией.
--signatureID или -s: идентификатор, назначаемый виджету подписи. (в случае, если несколько подписантов должны подписать один и тот же PDF-документ).
--pages или -p: страницы, которые нужно подписать.
--x_coordinate или -xи --y_coordinateили -y: указывает расположение подписи на странице.
--output_file или -o: путь к выходному файлу. Заполнение этого аргумента ограничено выбором файла в качестве входных данных, а не каталога.
--recursive или -r: обрабатывать папку рекурсивно или нет. Заполнение этого аргумента ограничено выбором каталога. 
'''

if __name__ == '__main__':
    # Синтаксический анализ аргументов командной строки, введенных пользователем
    # Parsing command line arguments entered by user
    args = parse_args()
    if args['load'] == True:
        load()
    else:
        # If File Path
        if os.path.isfile(args['input_path']):
            sign_file(
                password=args['password'], pk_filename=args['pk_filename'], sign_filename=args['sign_filename'],
                input_file=args['input_path'], signatureID=args['signatureID'],
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']), 
                pages=args['pages'], output_file=args['output_file']
            )
        # If Folder Path
        elif os.path.isdir(args['input_path']):
            # Process a folder
            sign_folder(
                password=args['password'], pk_filename=args['pk_filename'], sign_filename=args['sign_filename'],
                input_folder=args['input_path'], signatureID=args['signatureID'], 
                x_coordinate=int(args['x_coordinate']), y_coordinate=int(args['y_coordinate']),
                pages=args['pages'], recursive=args['recursive']
            )

'''
password=args['password'], pk_filename=args['pk_filename'], sign_filename=args['sign_filename'], 

'''

