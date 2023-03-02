
COMP=gcc
DIR:=bin
FLAGS:= -lrt
OBJS := $(addprefix $(DIR)/,tcp.o)
EXEC =$(addprefix $(DIR)/,tcp)

all: $(EXEC)

$(EXEC) : $(OBJS)
	$(COMP) -o $@ $^ $(FLAGS)

$(DIR)/%.o : %.c
	$(COMP) -c -o $@ $<

$(OBJS): | $(DIR)

$(DIR):
	mkdir $(DIR)

clean:
	rm $(EXEC) $(OBJS)
