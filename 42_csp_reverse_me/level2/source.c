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
  char input [24];
  char answer [9];

  printf("Please enter key: ");
  if (scanf("%23s", input) != 1) no();
  if (input[1] != '0') {
    no();
  }
  if (input[0] != '0') {
    no();
  }
  memset(answer,0,9);
  answer[0] = 'd';
    
  int pos = 2;
  int answer_pos = 1;

    while (pos + 2 < strlen(input) && answer_pos < 8) {
        char chunk[4];

        chunk[0] = input[pos];
        chunk[1] = input[pos + 1];
        chunk[2] = input[pos + 2];
        chunk[3] = '\0';

        int validation = atoi(chunk);
        answer[answer_pos] = (char)validation;

        pos += 3;
        answer_pos++;
    }
  answer[answer_pos] = '\0';

  validation = strcmp(answer,"delabere");
  if (validation == 0) {
    ok();
  }
  else {
    no();
  }
  return 0;
}
