DIR_OBJ         = ./.obj

IDIR            += ../../source/include/  ./

CFLAGS		+= $(addprefix -I, $(IDIR))
CFLAGS		+= $(addprefix -D, $(DEFS))

LIBA		:=  ../../.obj/libgmsdf.a 
LIBS		:= pthread  dl

LDFLAGS		:= $(addprefix -L, $(LDIR))
LDFLAGS		+= $(addprefix -l, $(LIBS))

OBJ            = $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir $(wildcard *.c)))

.PHONY: all


all:  $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBA) -o sm2

${DIR_OBJ}/%.o:%.c
	test -d $(DIR_OBJ) || mkdir -p $(DIR_OBJ)
	$(CC) $(CFLAGS) -c  $< -o $@

clean:
	$(RM) $(DIR_OBJ)/* *.o
