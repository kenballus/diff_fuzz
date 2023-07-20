CXX := afl-clang-fast++
CXXFLAGS := -Wall -Wextra -Os
IFLAGS := -Iboost

boost_url_target: boost_url_target.cpp boost/boost
	$(CXX) $(IFLAGS) $(CXXFLAGS) boost_url_target.cpp -o boost_url_target

boost/boost: get_boost.sh
	./get_boost.sh

.PHONY: clean
clean:
	rm -rf boost_url_target boost
