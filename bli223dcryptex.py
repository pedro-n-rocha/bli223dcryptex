################################################################
## credits : surrealiz3 __keep_0n_r0lling__ !! 
################################################################
## 
## BLI223 decryptor and decompressor 
## , 
## pub key extracted from memory  and BLI format semi decoded 
##... enough to extract , the same pvt key for all models from thomson , as far as
##  2007, 10 years ??!! >)  aint broken dont fix it !    
##
##  example : 
##
##  python bli223dcryptex.py st_tg582ndb_r10.2.5.2_bm.bin 
##
##  binwalk inflated_mst_tg582ndb_r10.2.5.2_bm.bin 
##
## I tested this on thousands BLI223 files and some very old , and all decrypt and decompress correctly.
## 
## Happy hunting :)  
## 

import struct
from hexdump import hexdump
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import zlib, sys

pubk = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzNQPMiyhMLXheXz8kxWt
+YtzImSKCJoXxmEPyYnQtpCKErvKmQ0kmosCi2+2Yq0hENX+JzfYQAtDTkBZz/BH
9+IcngHN6dbTvMp74rk78orY008VQON88twU/JdsNFU1mFQwL5Z+trqZ9ml3HRyb
z5rartrS2NK5YoQdGBskCCXEv4o/kK2/hJhAL7rgy9WYU8Dti57c30mJ68fA5zI9
wSi6pXRe28Wm6AqSKB+YICEgOF/RB355TQ94shnZBoHGXAS6aenYeZvjrAcgCSXI
VO1JrU7ebss/G2p/E6V+hw9bB7ilHwlFkJ4780bTynUx6YGCb1Dth9F9LN+IIcTV
dQIDAQAB
-----END PUBLIC KEY-----'''

rsa = RSA.importKey(pubk)


MUTE_SIZE = 6
ADDR_SIZE = 4
RSA_LEN = 256
AES_KEY_LEN = 32

if len(sys.argv) <= 1:
    print " \n *** provide file name argument RBI BLI .... !!!  \n  "
    exit()

fname = str(sys.argv[1])

f = open(fname,'rb')
fdata = f.read()
f.close()

mdata = bytearray(fdata)

print 'fdata len : 0x%x' %  len(fdata) 
#print 'mdata len : 0x%x' %  len(mdata)

hdrsize  = struct.unpack('>L' , fdata[0x28:0x2c])[0] 
datasize = struct.unpack('>L' , fdata[0x2c:0x30])[0]  

totallen = hdrsize + datasize 


print 'hdr len   : 0x%x ' % hdrsize
print 'data len  : 0x%x ' % datasize
print 'totallen  : 0x%x ' % totallen 
print 'diffsizes : 0x%s'  % (len(fdata) - totallen) 

#hexdump(fdata[hdrsize:hdrsize+MUTE_SIZE])

b2mutelen = struct.unpack('>L' , fdata[hdrsize+MUTE_SIZE:hdrsize+MUTE_SIZE+ADDR_SIZE])[0] 

print 'b2mutelen : 0x%x ' % b2mutelen

ptr1dec = hdrsize+MUTE_SIZE+ADDR_SIZE
b2posend = totallen - b2mutelen
print 'b2posend : 0x%x' % ( totallen - b2mutelen)
print 'ptr1dec : 0x%x ' % ptr1dec

rsadec1 = rsa.encrypt(fdata[ptr1dec:ptr1dec+RSA_LEN],None)[0]

hexdump(rsadec1)

print '-------------------------------------------'
hexdump(str(mdata[ptr1dec:ptr1dec+RSA_LEN]))


mdata[ptr1dec:ptr1dec+RSA_LEN] = rsadec1
#print '-------------------------------------------'
#hexdump(str(mdata[ptr1dec:ptr1dec+RSA_LEN]))

for ptr2 in range(0,len(rsadec1)):
    if rsadec1[ptr2] == b'\x00':
        break 

sdata = str(mdata)

b1pos = b2posend + ptr2 + 1 
print 'b1pos : 0x%x' % b1pos

hexdump(sdata[b1pos:b1pos+MUTE_SIZE])
b1mutelen = struct.unpack('>L' , sdata[b1pos+MUTE_SIZE:b1pos+MUTE_SIZE+ADDR_SIZE])[0] 

print 'b1mutelen : 0x%x ' % b1mutelen
b1posend = totallen - b1mutelen
print 'b1posend : 0x%x ' % b1posend

ptraes = b1posend - 1 
print 'ptraes : 0x%x' % ptraes

ptraes1 = b1pos + MUTE_SIZE + ADDR_SIZE
ptraes2 = ptraes1 + AES_KEY_LEN 

aesk = sdata[ptraes1:ptraes2]
hexdump(aesk)

print 'size: 0x%x'%( b1mutelen - ptraes)

blocks = b1mutelen  / 256
blocks += 1 
#blocks = (b1mutelen - ptraes) / 256
 
print 'blocks : 0x%x' % blocks


alldec=bytearray()
IV = 16 * '\x00'

d = sdata[ptraes2+(0*256):ptraes2+((0+1)*256)]
hexdump(d)

for x in range(0,blocks):
    d = bytearray(256)
    tmp = sdata[ptraes2+(x*256):ptraes2+((x+1)*256)]

    d[0:len(tmp)] = tmp    
    aes = AES.new(aesk.decode('hex'), AES.MODE_CBC, IV)
    #print len(d)
    dec = aes.decrypt(str(d))
    alldec += dec
    last= ptraes+((x+1)*256)

print '0x%x'% last

#o = open('compressed_'+fname, 'wb') 
#o.write(alldec)
#o.flush()
#o.close()

s2 = zlib.decompress(str(alldec[0x28:]))

o = open('inflated_'+fname, 'wb') 
o.write(s2)
o.flush()
o.close()

print " \n\n\n ***** PASS binwalk on this : inflated_"+fname+" \n\n"


