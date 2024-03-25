MAKEFLAGS = "-s"

##
## comp
##
CC_X64 	:= x86_64-w64-mingw32-gcc

##
## flags
##
CFLAGS  := -Os -fno-asynchronous-unwind-tables -fno-omit-frame-pointer -nostdlib
CFLAGS  += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS  += -s -ffunction-sections -falign-jumps=1 -w
CFLAGS  += -falign-labels=1 -fPIC -Wl,-Tscripts/linker.ld
CFLAGS  += -Wl,-s,--no-seh,--enable-stdcall-fixup
CFLAGS  += -Iinclude -masm=intel

ekko-x64: asm-x64
	@ echo "[*] building EKKO test [FLOWER_EKKO_OBF]..."
	@ $(CC_X64) bin/obj/*x64.o tests/Ekko.c src/Flower.c -o bin/test-ekko.x64.exe $(CFLAGS)
	@ python3 scripts/extract.py -f bin/test-ekko.x64.exe -o bin/test-ekko.x64.bin
	@ rm bin/test-ekko.x64.exe
	echo "[+] done"

foliage-x64: asm-x64
	@ echo "[*] building FOLIAGE test [FLOWER_FOLIAGE_OBF]..."
	@ $(CC_X64) bin/obj/*x64.o tests/Foliage.c src/Flower.c -o bin/test-foliage.x64.exe $(CFLAGS)
	@ python3 scripts/extract.py -f bin/test-foliage.x64.exe -o bin/test-foliage.x64.bin
	@ rm bin/test-foliage.x64.exe
	echo "[+] done"

asm-x64:
	@ echo "[*] building ASM stubs..."
	@ nasm -f win64 asm/Flower.x64.asm -o bin/obj/Flower.x64.o
	@ nasm -f win64 asm/Stub.x64.asm -o bin/obj/Stub.x64.o
	echo "[+] ASM stubs done cooking"


clean:
	@ echo "[*] cleaning up"
	@ rm -rf .idea
	@ rm -r bin/obj/*
	@ rm -rf bin/*.bin
	@ rm -rf bin/*.exe
	@ rm -rf cmake-build-debug