TARGET	=	filetype
CC		=	gcc
CFLAGS	=	-Wall -Wextra -Wpedantic -std=c11 -O2
SRC		=	main.c \
			filetype.c
OBJ		=	$(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ) filetype.h Makefile main.c filetype.c 
	$(CC) $(CFLAGS) $(OBJ) -o $(TARGET)

%.o: %.cpp Makefile main.c filetype.c 
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(TARGET)

re: fclean all
