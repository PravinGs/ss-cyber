# Makefile for C++ project with shared library

# Compiler and flags
CXX := g++
CXXFLAGS := -std=c++1z -Wall -Wextra -pedantic -fPIC
LDFLAGS := -shared  -lssl -lcrypto -lz -lpthread
LIB_DIR := /usr/local/lib
INC_DIR := /usr/local/include

# Directories
SRC_DIR := src
INCLUDE_DIR := include
OBJ_DIR := obj
BIN_DIR := bin

# Files
SRC := $(wildcard $(SRC_DIR)/*.cpp)
HEADERS := $(wildcard $(INCLUDE_DIR)/*.h)
OBJ := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRC))
TARGET := $(BIN_DIR)/libcyber-validator.so

# Targets
all: $(TARGET)

$(TARGET): $(OBJ)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp $(HEADERS)
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c -o $@ $<

deploy:
	@echo "Deploying library and headers..."
	@sudo cp $(TARGET) $(LIB_DIR)
	@sudo cp -r $(INCLUDE_DIR)/* $(INC_DIR)
	@sudo ldconfig
	@echo "Deployment complete."

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all clean


