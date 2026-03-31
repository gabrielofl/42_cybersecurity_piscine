NAME = stockholm
SRC = stockholm.py

all: $(NAME)

$(NAME): $(SRC)
	cp $(SRC) $(NAME)
	chmod +x $(NAME)

clean:
	rm -f $(NAME)

fclean: clean

re: fclean all

.PHONY: all clean fclean re