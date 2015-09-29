import os
import base64
import zlib
import hashlib

prefix = "asdfdsfadsf"
postfix = "dsfasdfasdf"

def encrpt(abc):
    return base64.encodestring( prefix + str(abc) + postfix ).strip('\n')

def decrpt(abc):
    fulltext = base64.decodestring(abc)
    a = fulltext.replace(prefix,'')
    b = a.replace(postfix,'')
    return b

def getBigFileMD5(filepath):
    if os.path.isfile(filepath):
        md5obj = hashlib.md5()
        maxbuf = 8192
        f = open(filepath,'rb')
        while True:
            buf = f.read(maxbuf)
            if not buf:
                break
            md5obj.update(buf)
        f.close()
        hash = md5obj.hexdigest()
        return str(hash)
    return None


