import base64
import zlib
prefix = "asdfdsfadsf"
postfix = "dsfasdfasdf"

def encrpt(abc):
    return base64.encodestring( prefix + str(abc) + postfix ).strip('\n')

def decrpt(abc):
    fulltext = base64.decodestring(abc)
    a = fulltext.replace(prefix,'')
    b = a.replace(postfix,'')
    return b


