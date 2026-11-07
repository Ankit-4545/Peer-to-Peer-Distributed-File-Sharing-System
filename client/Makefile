CXX = g++
CXXFLAGS = -std=c++11 -Wall -pthread

all: client

client: client.cpp files.cpp files.h peer.cpp peer.h
	$(CXX) $(CXXFLAGS) -o client client.cpp files.cpp peer.cpp

# tracker: tracker.cpp files.cpp files.h
# 	$(CXX) $(CXXFLAGS) -o tracker tracker.cpp files.cpp

clean:
	rm -f client *.o
