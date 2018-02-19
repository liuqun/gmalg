VERSION		:= 0.1
BASENAME	:= libgmsdf
STATICLIB	:= $(BASENAME).a
SHAREDLIB	:= $(BASENAME).so

DIR_OBJ		= ./.obj
SOURCES		= $(wildcard source/*.c)
OBJS		= $(patsubst %.c,${DIR_OBJ}/%.o,$(notdir ${SOURCES}))

export CC STRIP MAKE AR
.PHONY: all clean

all: $(OBJS)
	$(CC) $(CFLAGS) -o ${DIR_OBJ}/$(SHAREDLIB) $(OBJS)
	$(AR) -cr ${DIR_OBJ}/$(STATICLIB) $(OBJS)
	cp ${DIR_OBJ}/$(SHAREDLIB) lib/
	cp ${DIR_OBJ}/$(STATICLIB) lib/
	$(MAKE) -C utils

${DIR_OBJ}/%.o:source/%.c
	test -d $(DIR_OBJ) || mkdir -p $(DIR_OBJ)
	$(CC) $(CFLAGS) -c  $< -o $@

clean: 
	$(RM) ${DIR_OBJ}/*
	$(MAKE) -C utils clean

mrproper: clean
	$(RM) tags *.tgz

tarball:
	@git archive --prefix=$(BASENAME)-$(GIT_VER)/ --format=tar HEAD \
		| gzip > $(BASENAME)-$(GIT_VER).tgz
