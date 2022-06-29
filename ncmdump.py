#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__author__ = 'qyh / akinazuki'
__date__ = '2022/6/29 13:26'

import binascii
from importlib.resources import path
from ntpath import join
import struct
import base64
import json
import os
from sys import argv
from Crypto.Cipher import AES
from numpy import byte
from requests import request
import requests
from sympy import arg
from mutagen.easyid3 import EasyID3
from mutagen.mp3 import MP3
from mutagen.flac import FLAC,Picture
from mutagen.id3 import ID3, APIC, error

def dump(file_path, file_folder_name=None):
    # 十六进制转字符串
    core_key = binascii.a2b_hex("687A4852416D736F356B496E62617857")
    meta_key = binascii.a2b_hex("2331346C6A6B5F215C5D2630553C2728")
    def unpad(s): return s[0:-(s[-1] if type(s[-1]) == int else ord(s[-1]))]
    f = open(file_path, 'rb')
    header = f.read(8)
    # 字符串转十六进制
    assert binascii.b2a_hex(header) == b'4354454e4644414d'
    f.seek(2, 1)
    key_length = f.read(4)
    key_length = struct.unpack('<I', bytes(key_length))[0]
    key_data = f.read(key_length)
    key_data_array = bytearray(key_data)
    for i in range(0, len(key_data_array)):
        key_data_array[i] ^= 0x64
    key_data = bytes(key_data_array)
    cryptor = AES.new(core_key, AES.MODE_ECB)
    key_data = unpad(cryptor.decrypt(key_data))[17:]
    key_length = len(key_data)
    key_data = bytearray(key_data)
    key_box = bytearray(range(256))
    c = 0
    last_byte = 0
    key_offset = 0
    for i in range(256):
        swap = key_box[i]
        c = (swap + last_byte + key_data[key_offset]) & 0xff
        key_offset += 1
        if key_offset >= key_length:
            key_offset = 0
        key_box[i] = key_box[c]
        key_box[c] = swap
        last_byte = c
    meta_length = f.read(4)
    meta_length = struct.unpack('<I', bytes(meta_length))[0]
    meta_data = f.read(meta_length)
    meta_data_array = bytearray(meta_data)
    for i in range(0, len(meta_data_array)):
        meta_data_array[i] ^= 0x63
    meta_data = bytes(meta_data_array)
    meta_data = base64.b64decode(meta_data[22:])
    cryptor = AES.new(meta_key, AES.MODE_ECB)
    meta_data = unpad(cryptor.decrypt(meta_data)).decode('utf-8')[6:]
    meta_data = json.loads(meta_data)

    print(" - ID: %s" % meta_data['musicId'])
    print(" - Title: " + meta_data['musicName'])
    for i in range(0, len(meta_data['artist'])):
        print(" - Artist[{}]: {}".format(i+1, meta_data['artist'][i][0]))
    print(" - Album: " + meta_data['album'])
    if len(meta_data['alias']) > 0:
        print(" - Alias: " + meta_data['alias'][0])
    print(" - Format: " + meta_data['format'])
    print(" - Bitrate: " + str(meta_data['bitrate']))
    print(" - Duration: " + str(meta_data['duration']))

    crc32 = f.read(4)
    crc32 = struct.unpack('<I', bytes(crc32))[0]
    f.seek(5, 1)
    image_size = f.read(4)
    image_size = struct.unpack('<I', bytes(image_size))[0]
    image_data = f.read(image_size)

    output_filename = f.name.split(
        "/")[-1].split(".ncm")[0] + '.' + meta_data['format']
    # 输出到传入文件相同的目录
    if file_folder_name is None:
        output_path = os.path.join(
            os.path.split(file_path)[0], output_filename)
    else:
        # 输出到指定位置
        output_path = os.path.join(
            os.path.split(file_path)[0], file_folder_name)
    if file_folder_name != None and os.path.isdir(file_folder_name):
        # 输出到指定目录
        output_path = os.path.join(file_folder_name, output_filename)
    print('[*] Writing file: [%s]' % output_path)
    m = open(output_path, 'wb')
    chunk = bytearray()
    while True:
        chunk = bytearray(f.read(0x8000))
        chunk_length = len(chunk)
        if not chunk:
            break
        for i in range(1, chunk_length+1):
            j = i & 0xff
            chunk[i-1] ^= key_box[(key_box[j] +
                                   key_box[(key_box[j] + j) & 0xff]) & 0xff]
        m.write(chunk)
    m.close()
    f.close()
    print("[*] Extract [%s] success" % output_filename)
    print("[*] Adding ID3 tag")
    if meta_data['format'] == 'flac':
        audio = FLAC(output_path)
    else:
        audio = EasyID3(output_path)
    audio['title'] = meta_data['musicName']
    audio['album'] = meta_data['album']
    values = []
    for i in range(0, len(meta_data['artist'])):
        values.append(meta_data['artist'][i][0])
    audio['artist'] = '/'.join(values).strip()
    image_data = bytes(requests.get(meta_data['albumPic']).content)
    print("[*] Writing ID3 cover image")
    if type(audio) == FLAC:
        flac_image = Picture()
        flac_image.type = 3
        flac_image.mime = 'image/jpeg'
        flac_image.desc = 'Cover'
        flac_image.data = image_data
        audio.add_picture(flac_image)
        audio.save()
    if type(audio) == EasyID3:
        audio.save()
        audio = MP3(output_path)
        audio.tags.add(APIC(encoding=3, mime='image/jpeg', type=3, desc='Cover', data=image_data))
        audio.save()
    return file_name

if __name__ == '__main__':
    if len(argv) == 1:
        print("Usage: ncmdump.py <file/folder> <file/folder>")
        exit(1)
    file_name = argv[1]
    if os.path.isdir(file_name):
        print("[*] Dumping all files in %s" % file_name)
        for root, dirs, files in os.walk(file_name):
            for file in files:
                if file.endswith(".ncm"):
                    if len(argv) == 3:
                        print("[*] Extracting %s" %
                              os.path.join(argv[2], file))
                        dump(os.path.join(root, file), argv[2])
        exit(0)

    if len(argv) == 2:
        print("[*] Extracting %s" % file_name)
        dump(file_name)
    if len(argv) == 3:
        print("[*] Extracting %s" % file_name)
        dump(file_name, argv[2])