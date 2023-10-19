CC = g++
CFLAGS = -O3 -pedantic -Wall -Wextra -std=c99

TARGET = main

.PHONY: clean verify

$(TARGET).exe: $(TARGET).o sha256.o
	$(CC) $(CFLAGS) -o $(TARGET).exe $(TARGET).o sha256.o 

sha256.o: sha256.cpp 
	$(CC) $(CFLAGS) -c -o sha256.o sha256.cpp

$(TARGET).o: main.cpp
	$(CC) $(CFLAGS) -c -o $(TARGET).o main.cpp

clean:
	rm -f *.o $(TARGET).exe

run: $(TARGET).exe
	.\$(TARGET).exe