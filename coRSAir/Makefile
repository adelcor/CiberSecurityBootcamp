

NAME=corsair
SRC=main.c
OBJ=main.o
CC=gcc -g3
CFLAGS=-Wall -Wextra -Werror -fsanitize=address -g3
DIRSSL = -I${HOME}/.brew/opt/openssl@1.1/include
#DIRSSL = -I/openssl
RM=rm -rf
.c.o: $(SRC)
	@$(CC) $(FLAGS) $(DIRSSL) -c -o $@ $<
all: $(NAME)
$(NAME): $(OBJ)
	$(CC) $(CFLAGS) -o $(NAME)  -L${HOME}/.brew/opt/openssl@1.1/lib -lssl -lcrypto $(OBJ)
clean:
	@$(RM) $(OBJ)
fclean: clean
	@${RM} corsair
re: fclean all
.PHONY: all clean fclean re
