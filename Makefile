INC = /System/Volumes/Data/sgoinfre/goinfre/Perso/joslopez/homebrew/opt/openssl@3/include
LIB = /System/Volumes/Data/sgoinfre/goinfre/Perso/joslopez/homebrew/opt/openssl@3/lib
CFLAGS = -Werror -Wall -Wextra -Wno-deprecated-declarations
NAME = corsair

RED		=	\033[0;31m
RESET	= 	\033[0m

all: corsair

corsair: corsair.o
	gcc corsair.o -L$(LIB) -lssl -lcrypto -o corsair

corsair.o: corsair.c
	gcc -c corsair.c $(CFLAGS) -I$(INC) -o corsair.o

clean:
	@echo "$(RED)Cleaning$(RESET)"
	@rm -rf $(NAME) corsair.o cert1.pem cert2.pem encrypted_file.txt passwd.enc

fclean: clean
	@echo "$(RED)Removing: $(NAME)$(RESET)"
	@echo "$(RED)Removing: corsair.o$(RESET)"
	@echo "$(RED)Removing: cert1.pem cert2.pem encrypted_file.txt passwd.enc$(RESET)"

re:
	@$(MAKE) fclean
	@$(MAKE) all

generate:
	python3 generate.py

.PHONY: all clean fclean re