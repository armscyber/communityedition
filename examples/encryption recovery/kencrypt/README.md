# Simple File Encryption Recovery example
This example focuses on a ransomware encryptor that is designed to use a native legacy Windows library. By intercepting the encryption key material involved in the respective event, users can then decrypt the file after the fact. Below are the instructions to run and then decrypt the respective file.

Round trip demo
---------------
```
# Run a sample encrypter
kEncrypt.exe ./test/test1.txt test1.enc no

# Check the log and extract the key data
grep ExfilKeyData "C:/PublicDocuments/crypto.txt"

# Decrypt using the extracted data and compare to the original (should be same)
python decrypt-file.py -f test1.enc -o test1.out -x <keydata>
diff test1.out ./test/test1.txt
```
