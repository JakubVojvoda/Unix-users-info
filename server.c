/**
 *  
 *  Searching for information about users of Unix OS
 *  by Jakub Vojvoda [vojvoda@swdeveloper.sk]
 *  2013
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CANNOT_OPEN_FILE -1
#define PATTERN 10
#define BUFFER_LEN 1024
#define LOG 2
#define UID 3
#define L 0
#define U 1
#define G 2
#define N 3
#define H 4
#define S 5

typedef struct {
  int loru;
  char login[BUFFER_LEN][BUFFER_LEN];
  int uid[BUFFER_LEN];
  int item;
  int items[6];
} tArgs;

int handleMessage(char *message, tArgs *args);
int createAnswer(char *answer, tArgs args);
int itoa (int num, char *str, int base);

int main(int argc, char **argv)
{

 if (argc < 3 || (strcmp(argv[1], "-p") != 0)) {
    fprintf(stderr, "Failed: parameters\n");
    return EXIT_FAILURE;
  }

  int s, t, m;
  socklen_t sinlen;
  int port = atoi(argv[2]);
  struct sockaddr_in sin;
  char message[BUFFER_LEN];
  char answer[BUFFER_LEN];
  tArgs args;

  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Failed: create socket\n");
    return EXIT_FAILURE;
  }

  sin.sin_family = PF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr  = INADDR_ANY;

  if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) < 0 ) {
    fprintf(stderr, "Failed: bind socket\n");
    return EXIT_FAILURE;
  }

  if (listen(s, 10) != 0) {
    fprintf(stderr, "Failed: listen for connection\n");
    return EXIT_FAILURE;
  }

  sinlen = sizeof(sin);

  int answer_size = 0;
  int pid;

  while (1) {

    if ((t = accept(s, (struct sockaddr *) &sin, &sinlen)) < 0 ) {
      fprintf(stderr, "Failed: accept connection\n");
      return EXIT_FAILURE;
    }

    if ((pid = fork()) > 0) {
      bzero(message ,sizeof(message));

      if (read(t, message, sizeof(message) ) < 0) {
        fprintf(stderr, "Failed: read message\n");
        return EXIT_FAILURE;
      }

      int err;
      if (handleMessage(message, &args) == EXIT_FAILURE) {
        strcpy(answer, "Failed: wrong message format\n");
      }
      else {
        if (args.item) {
          if ((err = createAnswer(answer, args)) == CANNOT_OPEN_FILE)
            strcpy(answer, "Failed: open file\n");
          else if (err == EXIT_FAILURE)
            strcpy(answer, "Failed: create answer\n");
          answer_size = strlen(answer) + 1;
        }
        else {
          bzero(answer, sizeof(answer));
          answer_size = 1;
        }
      }

      /*
      printf("To %s (%s): %d send %dB\n",
             inet_ntoa(sin.sin_addr), hp->h_name, ntohs(sin.sin_port),answer_size);
      */

     if (write(t, answer, answer_size) <= 0) {
        fprintf(stderr, "Failed: write message\n");
        return EXIT_FAILURE;
      }

      for (m = 0; m < BUFFER_LEN; m++) {
        message[m] = '\0';
        answer[m] = '\0';
        args.uid[m] = -1;
      }

      args.loru = 0;
      int mm;
      for (mm = 0; mm < BUFFER_LEN; mm++) {
        for (m = 0; m < BUFFER_LEN; m++) {
          args.login[mm][m] = '\0';
        }
      }

      for (mm = 0; mm < 6; mm++)
        args.items[mm] = -1;
    }

    close(t);
  }

  if (close(t) < 0 || close(s) < 0) {
    fprintf(stderr, "Failed: close socket\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////

/*
  Creating an answer for corresponding request
*/
int createAnswer(char *answer, tArgs args)
{
  FILE *file;

  char *pattern = "^([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)\n$";
  regex_t re;
  regmatch_t pmatch[PATTERN];
  int stat = 0;
  char uknuid_buff[BUFFER_LEN];
  strcpy(uknuid_buff, "Unknown uid:\n");
  char uknlogin_buff[BUFFER_LEN];
  strcpy(uknlogin_buff, "Unknown login:\n");

  if (regcomp(&re, pattern, REG_EXTENDED) != 0) {
    fprintf(stderr, "Failed: regcomp\n");
    return EXIT_FAILURE;
  }

  if ((file = fopen("/etc/passwd", "r")) == NULL)
    return CANNOT_OPEN_FILE;

  strcpy(answer, "");
  char line[BUFFER_LEN];
  char h_msg[BUFFER_LEN];

  // searching by login (argument -l)
  if (args.loru == LOG) {
    int i = 0;
    int ranking = 1;
    int find = 0;
    int unknown_login = 0;

    while (strcmp(args.login[i], "") != 0) {

      while (fgets(line, BUFFER_LEN, file) != NULL) {

        stat = regexec(&re, line, PATTERN, pmatch, 0);

        if ((stat == 0) && (pmatch[1].rm_so >= 0) && (pmatch[1].rm_so >= 0)) {
          strncpy(h_msg, line+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
          h_msg[pmatch[1].rm_eo-pmatch[1].rm_so] = '\0';
        }
        else {
          i++;
          continue;
        }

        if (strcmp(h_msg, args.login[i]) == 0) {

          unknown_login++;
          while (ranking <= 6) {

            if ((args.items[L] == ranking) && pmatch[1].rm_so >= 0 && pmatch[1].rm_so >= 0) {
              strncat(answer, line+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[U] == ranking) && pmatch[3].rm_so >= 0 && pmatch[3].rm_so >= 0) {
              strncat(answer, line+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[G] == ranking) && pmatch[4].rm_so >= 0 && pmatch[4].rm_so >= 0) {
              strncat(answer, line+pmatch[4].rm_so, pmatch[4].rm_eo-pmatch[4].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[N] == ranking) && pmatch[5].rm_so >= 0 && pmatch[5].rm_so >= 0) {
              strncat(answer, line+pmatch[5].rm_so, pmatch[5].rm_eo-pmatch[5].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[H] == ranking) && pmatch[6].rm_so >= 0 && pmatch[6].rm_so >= 0) {
              strncat(answer, line+pmatch[6].rm_so, pmatch[6].rm_eo-pmatch[6].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[S] == ranking) && pmatch[7].rm_so >= 0 && pmatch[7].rm_so >= 0) {
              strncat(answer, line+pmatch[7].rm_so, pmatch[7].rm_eo-pmatch[7].rm_so);
              strcat(answer, " ");
              find++;
            }
            ranking++;
          }
          ranking = 1;
        }
        if (unknown_login > 0 && find)
          strcat(answer, "\n");
        find = 0;
      }

      if (!unknown_login) {
        strcat(uknlogin_buff, args.login[i]);
        strcat(uknlogin_buff, " ");
      }

      unknown_login = 0;
      fseek(file, 0, SEEK_SET);
      i++;
    }
    strcat(answer, uknlogin_buff);
    strcat(answer, "\n");
  }
  // searching by uid (argument -u)
  else if (args.loru == UID) {
    int i = 0;
    int uid;
    int ranking = 1;
    int find = 0;
    int unknown_uid = 0;
    char buff[BUFFER_LEN];

    int f;
    for (f = 0; f < BUFFER_LEN; f++)
      buff[f] = '\0';

    while (args.uid[i] != -1) {

      while (fgets(line, BUFFER_LEN, file) != NULL) {

        stat = regexec(&re, line, PATTERN, pmatch, 0);

        if ((stat == 0) && (pmatch[3].rm_so >= 0) && (pmatch[3].rm_so >= 0)) {
          strncpy(h_msg, line+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so);
          h_msg[pmatch[3].rm_eo-pmatch[3].rm_so] = '\0';
          uid = atoi(h_msg);
        }
        else {
          i++;
          continue;
        }

        if (uid == args.uid[i]) {

          unknown_uid++;
          while (ranking <= 6) {

            if ((args.items[L] == ranking) && pmatch[1].rm_so >= 0 && pmatch[1].rm_so >= 0) {
              strncat(answer, line+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[U] == ranking) && pmatch[3].rm_so >= 0 && pmatch[3].rm_so >= 0) {
              strncat(answer, line+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[G] == ranking) && pmatch[4].rm_so >= 0 && pmatch[4].rm_so >= 0) {
              strncat(answer, line+pmatch[4].rm_so, pmatch[4].rm_eo-pmatch[4].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[N] == ranking) && pmatch[5].rm_so >= 0 && pmatch[5].rm_so >= 0) {
              strncat(answer, line+pmatch[5].rm_so, pmatch[5].rm_eo-pmatch[5].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[H] == ranking) && pmatch[6].rm_so >= 0 && pmatch[6].rm_so >= 0) {
              strncat(answer, line+pmatch[6].rm_so, pmatch[6].rm_eo-pmatch[6].rm_so);
              strcat(answer, " ");
              find++;
            }
            if ((args.items[S] == ranking) && pmatch[7].rm_so >= 0 && pmatch[7].rm_so >= 0) {
              strncat(answer, line+pmatch[7].rm_so, pmatch[7].rm_eo-pmatch[7].rm_so);
              strcat(answer, " ");
              find++;
            }
            ranking++;
          }
          ranking = 1;
        }
        if (unknown_uid > 0 && find)
          strcat(answer, "\n");
        find = 0;
      }

      if (!unknown_uid) {
        itoa(args.uid[i], buff, 10);
        strcat(uknuid_buff, buff);
        strcat(uknuid_buff, " ");

        for (f = 0; f < BUFFER_LEN; f++)
          buff[f] = '\0';
      }

      unknown_uid = 0;
      fseek(file, 0, SEEK_SET);
      i++;
    }
    strcat(answer, uknuid_buff);
    strcat(answer, "\n");
  }

  fclose(file);
  return EXIT_SUCCESS;
}

/*
  Extraction of information from request
*/
int handleMessage(char *message, tArgs *args)
{
  char *pat1 = "^GET login:\n([^\n]*)\nITEMS/6([0-6]+)$";
  char *pat2 = "^GET uid:\n([^\n]*)\nITEMS/6([0-6]+)$";
  regex_t re1, re2;
  regmatch_t pmatch[PATTERN];
  char h_msg[BUFFER_LEN];
  char pars[BUFFER_LEN];

  if (regcomp(&re1, pat1, REG_EXTENDED) != 0)
    return EXIT_FAILURE;

  if (regcomp(&re2, pat2, REG_EXTENDED) != 0)
    return EXIT_FAILURE;

  if (regexec(&re1, message, PATTERN, pmatch, 0) == 0) {
    args->loru = LOG;
    if (pmatch[1].rm_so >= 0 && pmatch[1].rm_so >= 0) {
      strncpy(h_msg, message+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);

      int j = 0, x = 0, c = 0;
      int length = strlen(h_msg);

      for (x = 0; x < length; x++) {
        if (h_msg[x] != ' ') {
          args->login[j][c] = h_msg[x];
          c++;
        }
        else {
          j++;
          c = 0;
        }
      }
      strcpy(args->login[j], "");
    }
  }
  else if (regexec(&re2, message, PATTERN, pmatch, 0) == 0) {
    args->loru = UID;
    if (pmatch[1].rm_so >= 0 && pmatch[1].rm_so >= 0) {
      strncpy(h_msg, message+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
      char tmp[BUFFER_LEN][BUFFER_LEN];
      int j = 0, x = 0, c = 0;
      int length = strlen(h_msg);

      for (x = 0; x < length; x++) {
        if (h_msg[x] != ' ') {
          tmp[j][c] = h_msg[x];
          c++;
        }
        else {
          j++;
          c = 0;
        }
      }
      for (c = 0; c < j; c++)
        args->uid[c] = atoi(tmp[c]);
      args->uid[c] = -1;
    }
  }
  else
    return EXIT_FAILURE;

  args->item = 0;
  if (pmatch[2].rm_so >= 0 && pmatch[2].rm_so >= 0) {
    strncpy(pars, message+pmatch[2].rm_so, pmatch[2].rm_eo-pmatch[2].rm_so);
    int i;
    for (i = 0; i < 6; i++) {
      args->items[i] = pars[i] - '0';
      args->item += args->items[i];
    }
  }

  return EXIT_SUCCESS;
}

/*
  Integer to string conversion
*/
int itoa (int num, char *str, int base)
{
  int c;
  int len = 0;

  int x;
  for(x = num; x != 0; x/= base)
    len++;

  int j;
  for (j = 0; j < len +1; j++)
    str[j] = '\0';

  if (num == 0) {
    strcpy(str, "0");
    return EXIT_SUCCESS;
  }

  int i;
  for (i = len; i > 0; i--) {
    c = '0' + num % base;
    num /= base;
    str[i-1] = c;
  }
  str[len+1] = '\0';
  return EXIT_SUCCESS;
}
