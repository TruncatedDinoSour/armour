ifeq ($(NOQA),)
	CFLAGS += -std=c89 -ansi -Wall -Wextra -Wpedantic -pedantic -Wshadow -Werror -Wconversion -Wformat -Wuninitialized -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wredundant-decls -Wfloat-equal -Wcast-qual -Wnested-externs -Wvla -Winline -Wmissing-format-attribute -Wmissing-noreturn -pedantic-errors
	TESTCFLAGS += -g -Og
endif

CFLAGS += -fPIC -I$(realpath .) -I.
TESTCFLAGS += -fPIC -I$(realpath .) -I. -D_RUNTEST

LDFLAGS += -shared -lcrypto

LIB := armour
LIB_NAME := lib$(LIB).so

ROOT_DIR := ./armour/

SRC_DIRS := $(shell find $(ROOT_DIR) -type f -name '*.c' -exec dirname {} \; | sort | uniq)
OBJ_DIR := obj/

SRCS := $(shell find $(SRC_DIRS) -name '*.c')
OBJS := $(patsubst ./%.c,$(OBJ_DIR)/%.o,$(SRCS))

TEST_DIR := tests
PRETESTS := $(shell find $(TEST_DIR) -name 'pretest.py')
TESTS := $(shell find $(TEST_DIR) -name 'test:*.c')

all: $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: ./%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

pretest:
	for pt in $(PRETESTS); do \
		cd $$(dirname "$$pt") && python3 $$(basename "$$pt"); \
	done

compile_tests: $(LIB_NAME)
	for test in $(TESTS); do \
		cd $$(dirname "$$test") && $(CC) -o $$(basename "$$test.elf") $$(basename "$$test") $(TESTCFLAGS) -I$(realpath $(TEST_DIR)) -L$(realpath .) -l$(LIB); \
	done

clean_tests:
	rm -rf $(shell find $(TEST_DIR) -name '*.elf' -or -name '*.log' -or -name 'f:*')

run_tests:
	for test in $(TESTS); do \
		cd $$(dirname "$$test"); \
		LD_LIBRARY_PATH='$(realpath .)' ./"$$(basename "$$test.elf")" >stdout.log 2>stderr.log || echo "Test $$test failed. See log $$PWD/stderr.log" >&2 && echo "$$test passed. Log: $$PWD/stdout.log"; \
	done

test: pretest compile_tests run_tests clean_tests

.PHONY: clean pretest compile_tests clean_tests run_tests test

clean: clean_tests
	rm -rf $(OBJ_DIR) $(LIB_NAME)
