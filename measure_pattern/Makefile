CFLAGS += -O2 -Wall -march=native

all: slice slicemap

slice: main.c
	gcc main.c -o slice
slicemap: slicemap.c
	gcc slicemap.c -o slicemap

clean:
	rm -f slice slicemap