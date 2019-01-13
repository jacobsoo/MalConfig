#!/usr/bin/python

'''
    C&C extractor for SandroRat
    Reference : https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/
    by Jacob Soo Lead Re (jacob.soo@gmail.com)

    Hashes for samples:
    019ca14a8e0df140eb472770a9b0a90f8088fe98a53c3994c2093362c8e76719
    e4e32765e4e8645cdd9b15269e2c935aac74f8696ea6afa1c8bb1605113946db
    378bb5ef0c3dd470afddf0d45469653ef4b3c611a5444a5ed5078893a75674c3
    a6137fcf413ee4ae5bddc415bafdddf0ceb869f7be8542f763b6fdb04916115d
    c532a2588145825c1cbcd140192d100cfa9644ed3f2abf7ecbf000b563e9fa5f
'''

__author__ = "Jacob Soo Lead Re"
__version__ = "0.2"

import zipfile, sys, os, hashlib
import base64, urllib
import datetime
import argparse
from sys import argv
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm

#---------------------------------------------------
# _log : Prints out logs for debug purposes
#---------------------------------------------------
def _log(s):
    print(s)

#-------------------------------------------------------------------
# extract_config : This extracts the C&C information from SandroRat.
#-------------------------------------------------------------------
def extract_config(apkfile):
    a = apk.APK(apkfile)
    d = dvm.DalvikVMFormat(a.get_dex())
    string = ""
    for cls in d.get_classes():
        if 'Lnet/droidjack/server/MainActivity;'.lower() in cls.get_name().lower():
            for method in cls.get_methods():
                if '->onCreate('.lower() in str(method).lower():
                    for inst in method.get_instructions():
                        if inst.get_name() == 'sget-byte':
                            string = inst.get_output().split(',')[-1].strip(" '")
                            string, szMet = string.split("->")
                            break
    for cls in d.get_classes():
        if string.lower() in cls.get_name().lower():
            c2 = ""
            port = ""
            szTemp = None
            for method in cls.get_methods():
                if '<clinit>'.lower() in str(method).lower():
                    for inst in method.get_instructions():
                        if inst.get_name() == 'const-string':
                            c2 = inst.get_output().split(',')[-1].strip(" '")
                        if inst.get_name() == 'const/16':
                            port = inst.get_output().split(',')[-1].strip(" '")
                        if c2 and port:
                            break
            server = ""
            if port:
                server = "{0}:{1}".format(c2.replace("u'", ""), str(port))
            else:
                server = c2.replace("u'", "")
            _log('Extracting from %s' % apkfile)
            _log('C&C: [ %s ]\n' % server)
            hFile = open(apkfile, 'rb')
            contents = hFile.read()
            sha256_hash = hashlib.sha256(contents).hexdigest()
            md5 = hashlib.md5()
            for i in range(0, len(contents), 8192):
                md5.update(contents[i:i+8192])
            md5_hash = md5.hexdigest()
            hFile.close()
            readmeContents = '| Malware Family | SandroRat                                                    |\n' \
                             '| -------------- | ------------------------------------------------------------ |\n' \
                             '| **Date Added** | ' + str(datetime.datetime.now()) +'                                                   |\n' \
                             '| **MD5**        | '+ md5_hash +'                             |\n' \
                             '| **Sha256**     | '+ sha256_hash + ' |\n' \
                             '| **URL**        | -                                                            |\n' \
                             '| **C2**         | ' + server + ' |\n' \
                             '| **VirusTotal** | https://www.virustotal.com/#/file/'+ sha256_hash + '/detection |\n' \
                             '| **Koodous**    | https://koodous.com/apks/'+ sha256_hash + ' |\n' \
                             '|                | ![](../assets/'+ sha256_hash + '.png) |'
            hReadMe = open(md5_hash+".md", 'wb')
            hReadMe.write(readmeContents)
            hReadMe.close()


#-------------------------------------------------------------
# check_apk_file : Shitty Check whether file is a apk file.
#-------------------------------------------------------------
def check_apk_file(apk_file):
    bJar = False
    try:
        zf = zipfile.ZipFile(apk_file, 'r')
        lst = zf.infolist()
        for zi in lst:
            fn = zi.filename
            if fn.lower()=='androidmanifest.xml':
                bJar = True
                return bJar
    except:
        return bJar

#-------------------------------------------------------------
# logo : Ascii Logos like the 90s. :P
#-------------------------------------------------------------
def logo():
    print '\n'
    print ' ______     __  __     __     ______   ______        ______     ______     ______     __  __     ______     __   __   '
    print '/\  ___\   /\ \_\ \   /\ \   /\__  _\ /\  ___\      /\  == \   /\  == \   /\  __ \   /\ \/ /    /\  ___\   /\ "-.\ \  '
    print '\ \___  \  \ \  __ \  \ \ \  \/_/\ \/ \ \___  \     \ \  __<   \ \  __<   \ \ \/\ \  \ \  _"-.  \ \  __\   \ \ \-.  \ '
    print ' \/\_____\  \ \_\ \_\  \ \_\    \ \_\  \/\_____\     \ \_____\  \ \_\ \_\  \ \_____\  \ \_\ \_\  \ \_____\  \ \_\\\\"\_\\'
    print '  \/_____/   \/_/\/_/   \/_/     \/_/   \/_____/      \/_____/   \/_/ /_/   \/_____/   \/_/\/_/   \/_____/   \/_/ \/_/'
    print '\n'
    print " Find the C&C for this SandroRat mallie!"
    print " Jacob Soo"
    print " Copyright (c) 2016-2019\n"
                                                                                                                      

if __name__ == "__main__":
    description='C&C Extraction tool for SandroRat'
    parser = argparse.ArgumentParser(description=description,
                                     epilog='--file and --directory are mutually exclusive')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f','--file',action='store',nargs=1,dest='szFilename',help='filename',metavar="filename")
    group.add_argument('-d','--directory',action='store',nargs=1,dest='szDirectory',help='Location of directory.',metavar='directory')

    args = parser.parse_args()
    Filename = args.szFilename
    Directory = args.szDirectory
    is_file = False
    is_dir = False
    try:
        is_file = os.path.isfile(Filename[0])
    except:
        pass
    try:
        is_dir = os.path.isdir(Directory[0])
    except:
        pass
    logo()
    if Filename is not None and is_file:
        if check_apk_file(Filename[0])==True:
            extract_config(Filename[0])
        else:
            print("This is not a valid apk file : %s" % Filename[0])
    if Directory is not None and is_dir:
        for root, directories, filenames in os.walk(Directory[0]):
            for filename in filenames: 
                szFile = os.path.join(root,filename) 
                if check_apk_file(szFile)==True:
                    extract_config(szFile)
                else:
                    print("This is not a valid apk file : %s" % szFile)