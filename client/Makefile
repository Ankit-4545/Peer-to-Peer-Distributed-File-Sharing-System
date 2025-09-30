CXX = g++
CXXFLAGS = -std=c++11 -Wall

all: client

client: client.cpp files.cpp files.h
	$(CXX) $(CXXFLAGS) -o client client.cpp files.cpp

# tracker: tracker.cpp files.cpp files.h
# 	$(CXX) $(CXXFLAGS) -o tracker tracker.cpp files.cpp

clean:
	rm -f client *.o
