CC=gcc
CFLAGS=-Iinclude -Wall -O3 -c

BUILD_DIR=build
OBJECT_DIR=object
SOURCE_DIR=source

all: $(BUILD_DIR)/CuckooXtractor

clean:
	rm -f $(BUILD_DIR)/CuckooXtractor $(OBJECT_DIR)/*.o
	touch $(SOURCE_DIR)/*.c

$(BUILD_DIR)/CuckooXtractor: $(OBJECT_DIR)/Extractor.o $(OBJECT_DIR)/File.o
	$(CC) -o $(BUILD_DIR)/CuckooXtractor $(OBJECT_DIR)/Extractor.o $(OBJECT_DIR)/File.o

$(OBJECT_DIR)/Extractor.o: $(SOURCE_DIR)/Extractor.c
	$(CC) -o $@ $(CFLAGS) $(SOURCE_DIR)/Extractor.c

$(OBJECT_DIR)/File.o: $(SOURCE_DIR)/File.c
	$(CC) -o $@ $(CFLAGS) $(SOURCE_DIR)/File.c
