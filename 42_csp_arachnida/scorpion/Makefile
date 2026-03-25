CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -Iinclude -Ithird_party/libexif/include

NAME = scorpion
SRCS = src/main.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) /usr/lib/x86_64-linux-gnu/libexif.so.12.3.4 -o $(NAME)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f src/*.o

fclean: clean
	rm -rf $(NAME) data

re: fclean all