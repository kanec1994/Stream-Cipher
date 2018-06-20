all: run

run: ckane2_project1.o Stream_Cipher.o
	g++ -std=c++11 ckane2_project1.o Stream_Cipher.o -o run

ckane2_project1.o: ckane2_project1.cpp Stream_Cipher.hpp
	g++ -g -c -std=c++11 ckane2_project1.cpp

Stream_Cipher.o: Stream_Cipher.cpp Stream_Cipher.hpp
	g++ -g -c -std=c++11 Stream_Cipher.cpp

clean:
	rm -f run

