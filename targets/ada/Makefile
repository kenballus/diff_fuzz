CXX := afl-clang-fast++
CXXFLAGS := -Wall -Wextra -Os -std=c++17

ada_target: ada_target.cpp ada/singleheader/ada.cpp
	$(CXX) $(CXXFLAGS) ada_target.cpp ada/singleheader/ada.cpp -o ada_target

ada/singleheader/ada.cpp: get_ada.sh
	./get_ada.sh

.PHONY: clean
clean:
	rm -rf ada_target ada
