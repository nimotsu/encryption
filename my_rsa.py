import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aesss
import generate_rsa

# email
import smtplib 
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 

def read_key(key_name):
    if os.path.exists(key_name):
       with open(key_name, 'rb') as f:
           try:
            key = RSA.import_key(open(key_name).read())
            return key
           except :
            print('No ' + key_name + ' found.')
    else:
        return None

def encrypt_file(file_name='file.txt', key_name="receiver.pem"):
    file_in = open(file_name, "r")
    data = file_in.read().encode("utf-8")
    file_out = open(file_name, "wb")

    # recipient_key = RSA.import_key(open("receiver.pem").read())
    # key_name = "receiver.pem"
    recipient_key = read_key(key_name)
    if recipient_key is None:
        print('No '+key_name+' found.')
        return None
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

def decrypt_file(file_name='file.txt', key_name="private.pem"):
    file_in = open(file_name, "rb")

    # private_key = RSA.import_key(open("private.pem").read())
    # key_name = "private.pem"
    private_key = read_key(key_name)
    if private_key is None:
        print('No '+key_name+' found.')
        return None

    enc_session_key, nonce, tag, ciphertext = \
       [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # Saving decrypted file
    file_out = open(file_name, "wb")
    file_out.write(data)
    print(data.decode("utf-8"))

def send_key(key_name):
    filename = key_name
    fromaddr = ""
    toaddr = ""
       
    # instance of MIMEMultipart 
    msg = MIMEMultipart() 
    msg['From'] = fromaddr 
    msg['To'] = toaddr 
    msg['Subject'] = fromaddr+" Shared "+key_name+" Key with You"
      
    body = "Please keep the key safe!"
    msg.attach(MIMEText(body, 'plain')) 
    
    attachment = open(filename, "rb") 
      
    p = MIMEBase('application', 'octet-stream') 
    p.set_payload((attachment).read()) 
    encoders.encode_base64(p) 
    p.add_header('Content-Disposition', "attachment; filename= %s" % filename) 
      
    msg.attach(p) 
      
    # creates SMTP session 
    s = smtplib.SMTP('smtp.gmail.com', 587) 
    s.starttls() 
    s.login(fromaddr, "txokogamttdsylsg") 
    text = msg.as_string() 
    s.sendmail(fromaddr, toaddr, text) 
    s.quit()

def share_publick():
    key_name="receiver.pem"
    send_key(key_name)

def share_privatek():
    # generate_rsa.generate_key('share_pri.pem', 'share_pub.pem')
    key_name="private.pem"
    encrypt_file(key_name, 'share_pub.pem')
    send_key(key_name)
    decrypt_file(key_name, 'share_pri.pem')

def main():
    file_name ="file.txt"
    # encrypt_file(file_name)
    decrypt_file(file_name)
    # encrypt_file(file_name, 'share_pub.pem')
    # decrypt_file(file_name, 'share_pri.pem')
    # share_publick()
    share_privatek()

if __name__ == '__main__':
    main()

# hello
# can you read me? ;)