INC     =   /opt/homebrew/opt/openssl/include
LIB     =   /opt/homebrew/opt/openssl/lib
CFLAGS  =   -Werror -Wall -Wextra -Wno-deprecated-declarations
NAME	=	corsair

RED		=	\033[0;31m
RESET	= 	\033[0m

all:
	gcc corsair.c $(CFLAGS) -I$(INC) -L$(LIB) -lssl -lcrypto -o corsair

clean:
	@echo "$(RED)Cleaning$(RESET)"
	@rm -rf $(NAME)
	@echo "$(RED)Removed: $(NAME) folder$(RESET)"

fclean: clean
	@echo "$(RED)Removing: $(NAME)$(RESET)"
	@rm -rf $(NAME)

re:
	@$(MAKE) fclean
	@$(MAKE) all

.PHONY: all clean fclean re
#@./corsair ./Recursos/cert1.pem ./Recursos/cert2.pem ./Recursos/passwd.enc