import subprocess
import os

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

p0 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p0 = int(p0.stdout, 16)
p1 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p1 = int(p1.stdout, 16)
p2 = subprocess.run(["openssl", "prime", "-generate", "-bits", "256", "-hex"],
        stdout=subprocess.PIPE)
p2 = int(p2.stdout, 16)

n1 = p0 * p1
n2 = p0 * p2

e = 0x10001

r1 = (p0 - 1) * (p1 - 1)
r2 = (p0 - 1) * (p2 - 1)

d1 = modinv(e, r1)
d2 = modinv(e, r2)

e1_1 = d1 % (p0 - 1)
e1_2 = d1 % (p1 - 1)
e2_1 = d2 % (p0 - 1)
e2_2 = d2 % (p2 - 1)

coef1 = pow(p1, p0 - 2, p0)
coef2 = pow(p2, p0 - 2, p0)

with open("key1.conf", "w") as f:
    f.write("asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0\n")
    f.write("n=INTEGER:" + hex(n1) + "\n")
    f.write("e=INTEGER:" + hex(e) + "\n")
    f.write("d=INTEGER:" + hex(d1) + "\n")
    f.write("p=INTEGER:" + hex(p0) + "\n")
    f.write("q=INTEGER:" + hex(p1) + "\n")
    f.write("exp1=INTEGER:" + hex(e1_1) + "\n")
    f.write("exp2=INTEGER:" + hex(e1_2) + "\n")
    f.write("coeff=INTEGER:" + hex(coef1) + "\n")

with open("key2.conf", "w") as f:
    f.write("asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0\n")
    f.write("n=INTEGER:" + hex(n2) + "\n")
    f.write("e=INTEGER:" + hex(e) + "\n")
    f.write("d=INTEGER:" + hex(d2) + "\n")
    f.write("p=INTEGER:" + hex(p0) + "\n")
    f.write("q=INTEGER:" + hex(p2) + "\n")
    f.write("exp1=INTEGER:" + hex(e2_1) + "\n")
    f.write("exp2=INTEGER:" + hex(e2_2) + "\n")
    f.write("coeff=INTEGER:" + hex(coef2) + "\n")

os.system("openssl asn1parse -genconf key1.conf -out key1.der -noout")
os.system("openssl asn1parse -genconf key2.conf -out key2.der -noout")
os.system("openssl rsa -inform DER -outform PEM -in key1.der -out key1.pem")
os.system("openssl rsa -inform DER -outform PEM -in key2.der -out key2.pem")
os.system("openssl req -new -nodes -key key1.pem -out csr1.pem -subj /CN=ejemplo")
os.system("openssl req -new -nodes -key key2.pem -out csr2.pem -subj /CN=ejemplo")
os.system("openssl req -x509 -nodes -sha256 -days 36500 -key key1.pem -in csr1.pem -out cert1.pem")
os.system("openssl req -x509 -nodes -sha256 -days 36500 -key key2.pem -in csr2.pem -out cert2.pem")
os.system("rm -rf key1.conf key2.conf key1.der key2.der csr1.pem csr2.pem")

os.system("rm key1.pem key2.pem")

os.system("echo '42 Cibersegurity Bootcamp' > passwd.txt")
os.system("openssl x509 -pubkey -noout -in cert1.pem > pubkey.pem")
os.system("openssl pkeyutl -encrypt -inkey pubkey.pem -pubin -in passwd.txt -out passwd.enc")
os.system("echo 'You win!! This is the secret message.' > msg.txt")
os.system("openssl enc -in msg.txt -out encrypted_file.txt -e -aes256 -kfile passwd.txt")
os.system("rm pubkey.pem passwd.txt msg.txt")
