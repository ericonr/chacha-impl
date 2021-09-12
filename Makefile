CFLAGS := ${CFLAGS} -Wall -Wextra

all: libchacha.a

libchacha.a: chacha.o
	$(AR) r $@ $^

test: test-chacha
	./test-chacha

test-chacha: chacha.c
	$(CC) $(CFLAGS) -DTEST $< -o $@ $(LDFLAGS)
