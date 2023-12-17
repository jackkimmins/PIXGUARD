CXX := g++													# Compiler
CXXFLAGS := -std=c++20 -g -Wall								# Compiler flags
CPPFLAGS := -I/usr/include/cryptopp -I/usr/local/include	# Preprocessor flags
LDFLAGS := -L/usr/lib -L/usr/include/lib					# Linker flags
LDLIBS := -lcryptopp -lpng									# Libraries to link

SRC := src/main.cpp			# Source file
OBJ := $(SRC:.cpp=.o)	# Object file
EXEC := main			# Executable output

.PHONY: all clean

all: $(EXEC)  # Default target

$(EXEC): $(OBJ)  # Rule to create the executable
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:  # Clean target
	rm -f $(OBJ) $(EXEC)
