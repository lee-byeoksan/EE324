CXX=g++
OBJS=guess_password.o
SRCDIR=.
TARGET=guess_password
CXXFLAGS=--std=c++11

.PHONY: clean

all: $(TARGET)

$(TARGET): proj1/$(OBJS)
	$(CXX) $^ -o $@ -I. $(CXXFLAGS)

proj1/%.o: proj1/%.cpp
	$(CXX) -c $^ -o $@ -I. $(CXXFLAGS)

clean: FORCE
	rm -rf proj1/$(OBJS) $(TARGET)

FORCE:
