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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <netdb.h>

#define BUFF_LEN 1024
#define ANS 8192

#define PATTERN 1
#define PATT 5
#define L 0
#define U 1
#define G 2
#define N 3
#define H 4
#define S 5

#define WRONG_FORMAT 2
#define CANNOT_OPEN_FILE 3
#define CANNOT_CREATE_ANSW 4
#define CONNECT_FAIL 5


typedef struct {
  int port;
  char hostname[BUFF_LEN];
  char login[BUFF_LEN][BUFF_LEN];
  int uid[BUFF_LEN];
  int items[6];
} tParams;

int switch_counter = 1;

int getParams(tParams *par, int argc, char **argv);
int createMessage(tParams par, char *message);
int itoa (int num, char *str, int base);
int decodeAnswer(char *answer);


int main(int argc, char **argv)
{
  if (argc < 6) {
    fprintf(stderr, "Failed: parameters\n");
    return EXIT_FAILURE;
  }

  tParams par;

  if (getParams(&par, argc, argv) == EXIT_FAILURE) {
    fprintf(stderr, "Failed: parameters\n");
    return EXIT_FAILURE;
  }

  char message[BUFF_LEN];

  if (createMessage(par, message) == EXIT_FAILURE) {
    fprintf(stderr, "Failed: create message\n");
    return EXIT_FAILURE;
  }

  int s, n;
  struct sockaddr_in sin;
  struct hostent *hptr;
  char answer[ANS];

  if ((s = socket(PF_INET, SOCK_STREAM, 0 )) < 0) {
    fprintf(stderr, "Failed: create socket\n");
    return EXIT_FAILURE;
  }

  sin.sin_family = PF_INET;
  sin.sin_port = htons(par.port);

  if ((hptr = gethostbyname(par.hostname)) == NULL){
    fprintf(stderr, "Failed: get host name\n");
    return CONNECT_FAIL;
  }

  memcpy( &sin.sin_addr, hptr->h_addr, hptr->h_length);

  if (connect (s, (struct sockaddr *)&sin, sizeof(sin)) < 0 ){
    fprintf(stderr, "Failed: connect to server\n");
    return CONNECT_FAIL;
  }

  if (write(s, message, strlen(message) + 1) < 0 ) {
    fprintf(stderr, "Failed: write message\n");
    return EXIT_FAILURE;
  }

  if ((n = read(s, answer, sizeof(answer))) < 0) {
    fprintf(stderr, "Failed: read answer\n");
    return EXIT_FAILURE;
  }

  int k;
  if ((k = decodeAnswer(answer)) == WRONG_FORMAT) {
    fprintf(stderr, "Failed: wrong message format\n");
    return WRONG_FORMAT;
  }
  else if (k == CANNOT_OPEN_FILE) {
    fprintf(stderr, "Failed: open file\n");
    return CANNOT_OPEN_FILE;
  }
  else if (k == CANNOT_CREATE_ANSW) {
    fprintf(stderr, "Failed: create server answer\n");
    return CANNOT_CREATE_ANSW;
  }
  else if (k == EXIT_FAILURE) {
    fprintf(stderr, "Failed: regcomp\n");
    return EXIT_FAILURE;
  }

  if (close(s) < 0) {
    fprintf(stderr, "Failed: close socket\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/////////////////////////////////////////////////////////////////////////////////
/*
  Server answer decoding
*/
int decodeAnswer(char *answer)
{
  if (strcmp(answer, "Failed: wrong message format\n") == 0)
    return WRONG_FORMAT;

  if (strcmp(answer, "Failed: open file\n") == 0)
    return CANNOT_OPEN_FILE;

  if (strcmp(answer, "Failed: create answer for client\n") == 0)
    return CANNOT_CREATE_ANSW;

  char *pattern = "((.|\n)*)Unknown (login|uid):\n(.*)";
  regex_t re;
  regmatch_t pmatch[PATT];
  char h_buff[ANS];
  int i;
  int l_or_u = -1;

  if (regcomp(&re, pattern, REG_EXTENDED) != 0)
    return EXIT_FAILURE;

  if (regexec(&re, answer, PATT, pmatch, 0) == 0) {
    for (i = 0; i < ANS; i++)
      h_buff[i] = '\0';

    if (pmatch[1].rm_so >= 0 && pmatch[1].rm_so >= 0) {
      strncpy(h_buff, answer+pmatch[1].rm_so, pmatch[1].rm_eo-pmatch[1].rm_so);
      printf("%s", h_buff);

      for (i = 0; i < ANS; i++)
        h_buff[i] = '\0';
    }

    if (pmatch[3].rm_so >= 0 && pmatch[3].rm_so >= 0) {
      strncpy(h_buff, answer+pmatch[3].rm_so, pmatch[3].rm_eo-pmatch[3].rm_so);

      l_or_u = (strcmp(h_buff, "login") == 0) ? L : U;

      for (i = 0; i < ANS; i++)
        h_buff[i] = '\0';
    }

    if (pmatch[4].rm_so >= 0 && pmatch[4].rm_so >= 0) {
      strncpy(h_buff, answer+pmatch[4].rm_so, pmatch[4].rm_eo-pmatch[4].rm_so);

      char buff[BUFF_LEN];
      int j = 0;
      int m;

      for (m = 0; m < BUFF_LEN; m++)
        buff[m] = '\0';

      for (i = 0; i < strlen(h_buff) - 1; i++) {
        if (h_buff[i] != ' ' && h_buff[i] != '\n') {
          buff[j] = h_buff[i];
          j++;
        }
        else {
          if (l_or_u == L)
            fprintf(stderr, "Chyba: neznamy login ");
          else
            fprintf(stderr, "Chyba: neznamy uid ");
          fprintf(stderr, "%s\n", buff);
          for (m = 0; m < j; m++)
            buff[m] = '\0';
          j = 0;
        }
      }
    }
  }
  return EXIT_SUCCESS;
}

/*
  Extraction and verification of information
*/
int getParams(tParams *par, int argc, char **argv)
{
  int l_rank = 0;
  int u_rank = 0;
  int counter = 0;
  int j = 0;
  int p = 0, h = 0, l = 0, u = 0;
  int err = 0;

  char *pat1 = "(^[^-].*)";
  char *pat2 = "(^[0-9]+$)";
  regex_t re1, re2;
  regmatch_t pmatch[PATTERN];

  if (regcomp(&re1, pat1, REG_EXTENDED) != 0)
    return EXIT_FAILURE;

  if (regcomp(&re2, pat2, REG_EXTENDED) != 0)
    return EXIT_FAILURE;

  int x;
  for (x = 0; x < 6; x++)
    par->items[x] = 0;

  int i;
  for (i = 1; i < argc; i++) {
    counter++;
    if (strcmp(argv[i],"-p") == 0 && !p++) {
      i++;
      if (regexec(&re2, argv[i], PATTERN, pmatch, 0) == 0)
        par->port = atoi(argv[i]);
      else
        return EXIT_FAILURE;
    }
    else if (strcmp(argv[i],"-h") == 0 && !h++) {
      i++;
      strcpy(par->hostname, argv[i]);
    }
    else if ((strcmp(argv[i],"-l") == 0)) {
      l++;
      int k;
      for (k = 0; k < BUFF_LEN; k++)
        strcpy(par->login[k], "");

      l_rank = counter;
      i++;
      j = 0;
      int f, bl = 0;

      while (i < argc && (regexec(&re1, argv[i], PATTERN, pmatch, 0) == 0)) {
        for (f = 0; f <= j; f++)
          bl += ((strcmp(par->login[f], argv[i]) == 0) ? 1 : 0);

        if (!bl) {
          strcpy(par->login[j], argv[i]);
          j++;
        }
        bl = 0;
        i++;
      }
      i--;
      if (j <= 0) return EXIT_FAILURE;
    }
    else if ((strcmp(argv[i],"-u") == 0)) {
      u++;
      int k;
      for (k = 0; k < BUFF_LEN; k++)
        par->uid[k] = -1;
      u_rank = counter;
      i++;
      j = 0;
      int f, bl = 0;
      while (i < argc && (regexec(&re2, argv[i], PATTERN, pmatch, 0) == 0)) {
        for (f = 0; f <= j; f++)
          bl += (par->uid[f] == atoi(argv[i]) ? 1 : 0);

        if (!bl) {
          par->uid[j] = atoi(argv[i]);
          j++;
        }
        bl = 0;
        i++;
      }
      i--;
      if (j <= 0) return EXIT_FAILURE;
    }
    else if (regexec(&re1, argv[i], PATTERN, pmatch, 0) != 0) {
      int len = strlen(argv[i]);
      for (j = 1; j < len; j++) {
        switch (argv[i][j]) {
          case 'L':
            if (par->items[L])
              err = 1;
            par->items[L] = switch_counter;
            switch_counter++;
            break;
          case 'U':
            if (par->items[U])
              err = 1;
            par->items[U] = switch_counter;
            switch_counter++;
            break;
          case 'G':
            if (par->items[G])
              err = 1;
            par->items[G] = switch_counter;
            switch_counter++;
            break;
          case 'N':
            if (par->items[N])
              err = 1;
            par->items[N] = switch_counter;
            switch_counter++;
            break;
          case 'H':
            if (par->items[H])
              err = 1;
            par->items[H] = switch_counter;
            switch_counter++;
            break;
          case 'S':
            if (par->items[S])
              err = 1;
            par->items[S] = switch_counter;
            switch_counter++;
            break;
          default:
            return EXIT_FAILURE;
        }
      }
    }
    else
      return EXIT_FAILURE;
  }

  if (l_rank < u_rank) {
    int k;
    for (k = 0; k < BUFF_LEN; k++)
      strcpy(par->login[k], "");
  }
  else {
    int k;
    for (k = 0; k < BUFF_LEN; k++)
      par->uid[k] = -1;
  }

  if (p && h && (l || u) && !err)
    return EXIT_SUCCESS;

  return EXIT_FAILURE;
}

/*
  Creating a request
*/
int createMessage(tParams par, char *message)
{
  char h_msg[BUFF_LEN];

  if (par.uid[0] != -1) {
    int i = 0;

    strcpy(message, "GET uid:\n");
    while (par.uid[i] != -1) {
      itoa(par.uid[i], h_msg, 10);
      strcat(message, h_msg);
      strcat(message, " ");
      i++;
    }
  }
  else if (strcmp(par.login[0], "") != 0) {
    int j = 0;

    strcpy(message, "GET login:\n");
    while (strcmp(par.login[j], "") != 0) {
      strcat(message, par.login[j]);
      strcat(message, " ");
      j++;
    }
  }
  else
    return EXIT_FAILURE;

  strcat(message, "\n");
  strcat(message, "ITEMS/6");

  int d;

  for (d = 0; d < 6; d++) {
      itoa(par.items[d], h_msg, 10);
      strcat(message, h_msg);
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
