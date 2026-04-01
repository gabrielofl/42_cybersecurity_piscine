NAME = inquisitor

all: up

up:
	docker compose up --build

nb:
	docker compose up

down:
	docker compose down

clean: down
	docker compose down --volumes --remove-orphans

fclean: clean
	docker image rm -f $(NAME) 2>/dev/null || true
	docker system prune -f

re: fclean all

.PHONY: all up down clean fclean re nb