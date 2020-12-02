all: tcp-block

tcp-block: main.cpp
	g++ -o tcp-block main.cpp -lpcap

clean:
	rm -f tcp-block

