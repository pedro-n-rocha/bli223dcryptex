import sys
import binascii
import struct
import hashlib
import zlib, sys
from Crypto.PublicKey import RSA

import hexdump


#reversed and captured from stage2 bootloader /  extrator for S2 BL from CFE to retreive the key 
pubk = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzNQPMiyhMLXheXz8kxWt
+YtzImSKCJoXxmEPyYnQtpCKErvKmQ0kmosCi2+2Yq0hENX+JzfYQAtDTkBZz/BH
9+IcngHN6dbTvMp74rk78orY008VQON88twU/JdsNFU1mFQwL5Z+trqZ9ml3HRyb
z5rartrS2NK5YoQdGBskCCXEv4o/kK2/hJhAL7rgy9WYU8Dti57c30mJ68fA5zI9
wSi6pXRe28Wm6AqSKB+YICEgOF/RB355TQ94shnZBoHGXAS6aenYeZvjrAcgCSXI
VO1JrU7ebss/G2p/E6V+hw9bB7ilHwlFkJ4780bTynUx6YGCb1Dth9F9LN+IIcTV
dQIDAQAB
-----END PUBLIC KEY-----'''

enc = RSA.importKey(pubk)


if len(sys.argv) <= 1:
    print " \n *** provide file name argument !!!  \n  "
    exit()

fname = str(sys.argv[1])

f = open(fname , 'rb')
data = f.read()
f.close()

crypt = data[52:308] 
hcrypt =  binascii.hexlify(crypt)

hdrsize  = struct.unpack('>L' , data[40:44])[0] 
datasize = struct.unpack('>L' , data[44:48])[0]  

totalsize = hdrsize + datasize

sha1data = bytearray(totalsize)
sha1data[:] = data[:totalsize]


for x in range(0,256):
    sha1data[52+x] = 0

decrypted = enc.encrypt(binascii.unhexlify((hcrypt)),None)[0]


print 'decrypted : '
hexdump.hexdump(decrypted)



for x in range(0,len(decrypted)) : 
    if  decrypted[x] == b'\x00' :
          p = x +1
          break


hmac = binascii.hexlify( decrypted[p:len(decrypted)])
#print hmac 
digest = hashlib.sha1(sha1data).hexdigest()
#print digest

#if hmac == digest : 
#    print "match"

crypt2 = data[361:617]
hcrypt2 =  binascii.hexlify(crypt2)
decrypted2 = enc.encrypt(binascii.unhexlify((hcrypt2)),None)[0]

print 'decrypted2:'
hexdump.hexdump(decrypted2)

aeskey = decrypted2[20:52]


print 'aeskey:'
hexdump.hexdump(aeskey)       


#print totalsize

#s = hashlib.sha1(sha1data).hexdigest()
#print s


vletters = { 1 : '1' , 2 : '2' , 3 : '3' , 4 : '4' , 5 : '5' , 6 : '6' , 7 : '7' , 8 : '8' , 9 : '9' ,
        10 : 'A' , 11 : 'B' , 12 : 'C' , 13 : 'D' , 14 : 'E' , 15 : 'F' , 16 : 'G' , 17 : 'H' , 18 : 'I' , 19 : 'J' ,
        20 : 'K' , 21 : 'L' , 22 : 'M' , 23 : 'N' , 24 : 'O' , 25 : 'P' , 26 : 'Q' , 27 : 'R' , 28 : 'S' , 29 : 'T' , 
        30 : 'U' , 31 : 'V' , 32 : 'W' , 33 : 'X' , 34 : 'Y' , 35 : 'Z'
        }           


version = "%s.%s.%s.%s" % ( struct.unpack('B' , data[32:33])[0] ,  struct.unpack('B' , data[33:34])[0] ,  struct.unpack('B' , data[34:35])[0] , vletters[ struct.unpack('B' , data[35:36])[0]] ) 
        
#print version 
#hardcoded lenghts ...   

print '\n********* fw fixed header decoding ********************************************************************* \n'  
print ' [ptr :          ] filname           : '  + fname  
print ' [ptr : 000      ] imagetype         : '  + data[0:9] 
print ' [ptr : 006      ] FIACODE           : '  + data[6:8]
print ' [ptr : 020      ] branding          : '  + data[20:22] 
print ' [ptr : 028      ] flag??            : '  + binascii.hexlify(data[28:32])  
print ' [ptr : 032      ] version           : '  + version # binascii.hexlify(data[32:36])  
print ' [ptr : 040      ] hdrlength         : 0x'+ binascii.hexlify(data[40:44])  
print ' [ptr : 044      ] datalength        : 0x'+ binascii.hexlify(data[44:48]) 
print ' [ptr : 048      ] crc32             : '  + binascii.hexlify(data[48:52])  + '' # does this still applys ?? dont think so 
print ' [ptr :          ] computedhash      : '  + digest
print ' [ptr :          ] decryptedhash     : '  + hmac
print ' [ptr :          ] integritycheck    : '  + ('\033[92m'+'True'+'\033[0m' if hmac == digest else '\033[91m'+'False'+'\033[0m')
print ' [ptr :          ] aeskey            : '  + binascii.hexlify(aeskey)                                                         

 # + ' ' + fname
#print ' [ptr : 052      ] flag52    : '+binascii.hexlify(data[52:56])  + ''
#print ' [ptr : 060      ] val??     : '+binascii.hexlify(data[60:64])  + ''

#print hdrsize
#print totalsize + 16

print ' [prt : 0x%x ] footer            : %s '% (totalsize ,  data[totalsize:len(data)])

# chek after hdrsize some images corrupted ??? 
print ' [ptr : %d      ] imagetype         : %s'  % (hdrsize +1 ,  data[ hdrsize +1 : hdrsize + 5  ])

#print ' [ptr : siz ] hdrend    : '+data[+'


desc = {
        '08': 'board             :',
        '09': 'model1            :',
        '0a': 'model2            :',
        '20': '?????             :',
        '81': 'flashaddr         :',
        }


ptr = 308

def crawl( ptr , n ) :
    t =  binascii.hexlify(data[ptr])
    ptr += 1
    len = ord(data[ptr])
    ptr += 1 

    if t in desc :
        k = desc[t]
    else:
        k = ' undefined :'

    
    if t == '08' or t == '09' or t == '20' or t == '0a':
        #print k+' '+data[ptr:ptr+len] + 'ptr : %d' + ptr
        print ' [ptr : %3d      ] %s %s ' %  (ptr, k , (data[ptr:ptr+len]))

        
        
    else:
#        print k+' '+binascii.hexlify(data[ptr:ptr+len]) + 'ptr : %d' % ptr
        print ' [ptr : %3d      ] %s %s ' % (ptr, k , (binascii.hexlify(data[ptr:ptr+len])))
 
    ptr = ptr+len
    n -=1
    return ptr if n == 0 else  crawl(ptr , n) 
   

ptr = crawl(ptr , 5 ) 


#print ' typefield : '+binascii.hexlify(data[308])  + ' <--- type of field thats follows'
#print ' len       : %d' % (ord(data[309])) 
#print ' field1    : '+data[310:310+6] + ' <--- boardtype' 
#print ' typefield : '+binascii.hexlify(data[316:317])  + ' '
#print ' len       : %d' % (ord(data[317:318])) 
#print ' field2    : '+(data[318:318+21])  + ' '
#print ' typefield : '+binascii.hexlify(data[339:340])  + ' '
#print ' len       : %d' % (ord(data[340:341])) 
#print ' field3    : '+(data[341:341+3])  + ' '
#print ' typefield : '+binascii.hexlify(data[344:345])  + ' '
#print ' len       : %d' % (ord(data[345:346]))
#print ' field4    : '+(data[346:346+9])  + ' '
#print ' typefield : '+binascii.hexlify(data[355:356])  + ' '
#print ' len       : %d' % (ord(data[356:357]))
#print ' field4    : '+binascii.hexlify((data[357:357+4]))  + ' flash start address '
#print ' typefield : '+binascii.hexlify(data[361:362])  + ' '
#print ' len       : %d' % (ord(data[362:363]))

#print 'final_ptr: %d' % ptr
print '\n******************************************************************************************************** \n'
