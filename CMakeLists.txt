cmake_minimum_required(VERSION 3.26)
project(flower C)

set(CMAKE_C_STANDARD 23)

include_directories( include )


add_executable(flower
        include/Flower.h
        src/Flower.c
        include/Native.h
        tests/Foliage.c
        tests/Ekko.c
        include/Stub.h
)