#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void no(void) {
  puts("Nope.");
  exit(1);
}

void ok(void) {
  puts("Good job.");
  return;
}


int main(void) {
  size_t len;
  int validation;
  char local_3d;
  char local_3c;
  char local_3b;
  int pos;
  int local_14;
  char input [24];
  char answer [9];
  int flag = 1;

  printf("Please enter key: ");
  if (scanf("%23s", input) != 1) no();
  if (input[1] != '0') {
    no();
  }
  if (input[0] != '0') {
    no();
  }
  fflush(stdin);
  memset(answer,0,9);
  answer[0] = 'd';
    
  while( true ) {
    len = strlen(answer);
    flag = 1;
    if (len < 8) {
      len = strlen(input);
      flag= input < len;
    }
    if (!flag) break;
    local_3d = input[pos];
    local_3c = input[pos + 1];
    local_3b = input[pos + 2];
    validation = atoi(&local_3d);
    answer[local_14] = (char)validation;
    pos = pos + 3;
    local_14 = local_14 + 1;
  }
  answer[local_14] = '\0';
  validation = strcmp(answer,"delabere");
  if (validation == 0) {
    ok();
  }
  else {
    no();
  }
  return 0;
}
