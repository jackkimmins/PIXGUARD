# Makefile for AES Encryption/Decryption program

CXX := g++                     # Compiler
CXXFLAGS := -std=c++20 -g -Wall  # Compiler flags
CPPFLAGS := -I/usr/include/cryptopp -I/usr/local/include
LDFLAGS := -L/usr/lib -L/usr/include/lib
LDLIBS := -lcryptopp -lpng     # Libraries to link

SRC := main.cpp  # Source file
OBJ := $(SRC:.cpp=.o)  # Object file
EXEC := main  # Executable output

.PHONY: all clean

all: $(EXEC)  # Default target

$(EXEC): $(OBJ)  # Rule to create the executable
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:  # Clean target
	rm -f $(OBJ) $(EXEC)
