#!/usr/bin/python
from androguard.misc import *
import sys
from Crypto.Cipher import ARC4
from androguard.core.androconf import show_logging
import logging
from base64 import b64decode

show_logging(level=logging.FATAL)

def dropDex(apkname):
    try:
        a,d,dx= AnalyzeAPK(apkname)
    except Exception as e:
        print(e)
        return

    for c in dx.get_classes():
        for m in c.get_methods():
            try:
                source = m.get_method().get_source()
                if "length" in source:
                    y = m.get_xref_from()
                    dexobj = list(y)[0][1].get_source()
                    v = re.findall(" (.{2,5}) = .{2,5}length",source)
                    v2 = re.findall(" % (.{2,5})\)\]",source)
                    ss = re.findall("= {(.{100,300})};",dexobj)
                    if len(v)>0:
                        if len(ss) > 0 and v[0] == v2[0]:
                            key = re.findall("(-?[0-9]+),?",ss[0])
                            key = list(map(lambda x: int(x)&0xff,key))
                            print("Key : {}".format(key))
                            key = b''.join(list(map(bytes,[key])))
                            image_list = a.get_files()
                            for fil in image_list:
                                fullsize = a.get_file(fil)
                                rc4 = ARC4.new(key)
                                dec = rc4.decrypt(fullsize[4:])
                                if dec[:2] == b'PK':
                                    filesize = int.from_bytes(fullsize[0:4],byteorder='little')
                                    print("[+] Filesize = {}".format(filesize))
                                    print("[+] Zip header found. Writing file : {}".format(sys.argv[1]+".decrypted"))
                                    dexname = sys.argv[1]+".decrypted"
                                    f = open(dexname,"wb")
                                    f.write(dec[:filesize])
                                    f.close()
                                    return dexname
            except:
                pass

def v25(source):
    lines = source.split("\n")
    c2 = lines[10]
    key = lines[14]

    if "https" not in source:

        c2a = re.search("\(\"(.*)\"\)",c2).group(0)
        s1 = c2a[1:-1].replace("\"","").split(", ")
        s1_d = b64decode(s1[0]).decode("utf-8")
        c = ARC4.new(s1[1])
        panel = c.decrypt(bytes.fromhex(s1_d)).decode("utf-8")

    else :
        panel = re.findall("= \"(.*)\";",c2)[0]


    keya = re.search("\(\"(.*)\"\)",key).group(0)
    s2 = keya[1:-1].replace("\"","").split(", ")
    s2_d = b64decode(s2[0]).decode("utf-8")
    c2 = ARC4.new(s2[1])
    key = c2.decrypt(bytes.fromhex(s2_d)).decode("utf-8")


    print("C2: {}\nKey: {}".format(panel,key))

def v24(source):
    lines = source.split("\n")
    c2 = lines[6].strip().split("\"")[1]
    key = lines[10].strip().split("\"")[1]
    print("C2: {}\nKey: {}".format(c2,key))


def dropC2(dexname):
    d = AnalyzeAPK(dexname)
    bad_classes = ["/ooooooooooooooooo;","/oooooooooooooooooo;","/ooooooooooooooooooo;","/a;","/b;", "/c;"]
    possible = []
    for i in d[1][0].get_classes():
        if i.name.count("/") == 3:
            for c in bad_classes:
                if c in i.name:
                    possible.append(d[1][0].get_class(i.name))

    for c in possible:
        done = False
        for m in c.get_methods():
            try:
                source = m.get_source()

                if source.count("this") < 55 and source.count("this") > 49:
                    v25(source)
                    return


                if source.count("this") < 22 and source.count("this") > 18:
                    if "http" in source:
                        v24(source)
                        return


            except Exception as e :
                pass

        if done:
            break


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage python getpayload.py pathtoapk.apk")
        exit()

    dexname = dropDex(sys.argv[1])
    if dexname != None:
        dropC2(dexname)



