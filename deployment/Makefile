# Function to check required arguments
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1))

CC = clang
CFLAGS = -I../tinycrypt/lib/include
LDFLAGS = -L../tinycrypt/lib -ltinycrypt

all: global_secrets.h

global_secrets.h: gen_key
	./gen_key

gen_key: gen_key.c
	$(CC) $(CFLAGS) gen_key.c $(LDFLAGS) -o gen_key

clean:
	rm -f global_secrets.h gen_key
