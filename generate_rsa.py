from Crypto.PublicKey import RSA

def generate_key(private_file="private.pem", public_file="receiver.pem"):
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(private_file, "wb")
    file_out.write(private_key)


    public_key = key.publickey().export_key()
    file_out = open(public_file, "wb")
    file_out.write(public_key)

def main():
    generate_key()
    # generate_key('share_pri.pem', 'share_pub.pem')

if __name__ == '__main__':
    main()