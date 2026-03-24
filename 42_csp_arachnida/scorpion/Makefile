CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -Iinclude
EXIF_CFLAGS := $(shell pkg-config --cflags libexif)
EXIF_LIBS := $(shell pkg-config --libs libexif)

NAME = scorpion
SRCS = src/main.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) $(EXIF_CFLAGS) $(OBJS) $(EXIF_LIBS) -o $(NAME)

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) $(EXIF_CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o

fclean: clean
	rm -rf $(NAME) data

re: fclean all