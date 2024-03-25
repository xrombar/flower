#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import pefile
import argparse

def main():
    parser = argparse.ArgumentParser(description="extract shellcode from PE")
    parser.add_argument('-f', required=True, help="path to the source exe", type=str)
    parser.add_argument('-o', required=True, help="path to the store the output shc", type=str)
    option = parser.parse_args()

    exe = pefile.PE(option.f)
    sec = exe.sections[0].get_data()

    if sec.find(b'LEMON SOJU') != None:
        raw = sec[:sec.find(b'LEMON SOJU')]
        f = open(option.o, 'wb+')
        f.write(raw)
        f.close()
    else:
        print('[!] error: no ending tag')

if __name__ in '__main__':
    try:
        main()
    except Exception as e:
        print(f"[!] error: {e}")