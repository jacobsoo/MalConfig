#!/usr/bin/python

'''
    C&C extractor for Telecom Fraud Network for South Koreans
    Reference : http://blogs.360.cn/post/telecom_fraud_network_for_Korea.html
    by Jacob Soo Lead Re (jacob.soo@gmail.com)

    Hashes for samples:
    44b74792c45cdda2432cbca5a3788392cfbd40c9f3df733fd4ea7fc12d6cff93 
    d03186a5903a0f30ca5cbaec6867df631e313c39f344ee0f1c465c12352a4608 
    b45a535e4791dd17713f70e0a9ed2d5ec4e914f545e97e57b62d2e085c30f91e 
    c15323718279c9f29ddd359920d7fe6b7356078bae67d81169fd4b9c15a8dc27 
    0eef59d4a6e61c38c5e43d0ca6890f1cef9329f10c0901ace9197dc2bb8abf64 
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
    szFTPUsername = ""
    szFTPPassword = ""
    szC2 = ""
    for cls in d.get_classes():
        if 'Lcom/android/csi/common/WifiGlobal;'.lower() in cls.get_name().lower():
            for field in cls.get_fields():
                if "g_ftppassword".lower() in str(field).lower():
                    szFTPUsername = field.get_init_value().get_value()
                elif "g_ftpusername".lower() in str(field).lower():
                    szFTPPassword = field.get_init_value().get_value()
                elif "g_managerurl".lower() in str(field).lower():
                    szC2 = field.get_init_value().get_value()
    if szFTPPassword and szFTPUsername and szC2:
        for i in range(1,6):
            szC2 = base64.b64decode(szC2)
        _log('[+] Extracting from %s' % apkfile)
        _log('[+] FTP Username : [ %s ]' % szFTPUsername)
        _log('[+] FTP Password : [ %s ]' % szFTPPassword)
        _log('[+] C&C: [ %s ]\n' % szC2)
        hFile = open(apkfile, 'rb')
        contents = hFile.read()
        sha256_hash = hashlib.sha256(contents).hexdigest()
        md5 = hashlib.md5()
        for i in range(0, len(contents), 8192):
            md5.update(contents[i:i+8192])
        md5_hash = md5.hexdigest()
        hFile.close()
        readmeContents = '| Malware Family | Telecom Fraud Network for South Koreans                      |\n' \
                         '| -------------- | ------------------------------------------------------------ |\n' \
                         '| **Date Added** | ' + str(datetime.datetime.now()) +'                                                   |\n' \
                         '| **MD5**        | '+ md5_hash +'                             |\n' \
                         '| **Sha256**     | '+ sha256_hash + ' |\n' \
                         '| **URL**        | -                                                            |\n' \
                         '| **FTP Username**        | '+ szFTPUsername + '                                                            |\n' \
                         '| **FTP Password**        | '+ szFTPPassword + '                                                            |\n' \
                         '| **C2**         | ' + szC2 + ' |\n' \
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
    print " Find the C&C for this TelcoFraud mallie!"
    print " Jacob Soo"
    print " Copyright (c) 2016-2019\n"
                                                                                                                      

if __name__ == "__main__":
    description='C&C Extraction tool for TelcoFraud'
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