CC ?= gcc
CXX ?= g++

all: slice slicemap oneslice_attacker

slice: main.c
	gcc main.c -o slice
slicemap: slicemap.c
	gcc slicemap.c -o slicemap
oneslice_attacker: oneslice_attacker.cpp
	$(CXX) -O2 -pthread -o oneslice_attacker oneslice_attacker.cpp
clean:
	rm -f slice slicemap oneslice_attacker
