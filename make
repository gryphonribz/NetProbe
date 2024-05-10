CC=gcc
CXX=g++
CFLAGS=-Wall -I/usr/include/json-c -I/usr/include/openssl -I/path/to/wappalyzer/include
CXXFLAGS=-Wall -I/usr/include/json-c -I/usr/include/openssl -I/path/to/wappalyzer/include
LDFLAGS=-L/usr/lib -L/path/to/wappalyzer/lib
LDLIBS=-lssl -lcrypto -lcurl -ljson-c -lwappalyzer -lstdc++ -lm

# Assuming your source files are named appropriately
SRC=NetProbe.c
OBJ=$(SRC:.c=.o)

# Output executable
EXEC=website_info

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)

.PHONY: all clean 
