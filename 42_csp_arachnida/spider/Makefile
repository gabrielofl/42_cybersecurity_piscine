CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -Iinclude
SRC = src/main.cpp
OBJ = $(SRC:.cpp=.o)
NAME = spider

all: $(NAME)

$(NAME): $(OBJ)
	$(CXX) $(CXXFLAGS) $(OBJ) -lcurl -o $(NAME)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

run: $(NAME)
	./$(NAME) --help

clean:
	rm -f src/*.o

fclean: clean
	rm -rf $(NAME) data/

re: fclean all

.PHONY: all run clean fclean re
