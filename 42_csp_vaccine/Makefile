dvwa:
	docker run -it -d --name dvwa -p 80:80 vulnerables/web-dvwa

stop:
	-docker stop $$(docker ps -q)

fclean: stop
	docker rmi $$(docker image ls -q)