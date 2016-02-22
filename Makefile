###########################################################
#
#  Searching for information about users of Unix OS
#  by Jakub Vojvoda [vojvoda@swdeveloper.sk]
#  2013
#
###########################################################

CLIENT=client
SERVER=server
CC=gcc
CFLAGS=-Wall -g

all:
	gcc $(CLIENT).c $(CFLAGS) -o $(CLIENT)
	gcc $(SERVER).c $(CFLAGS) -o $(SERVER)

clean:
	rm -rf $(CLIENT).o $(SERVER).o $(CLIENT) $(SERVER) *~
