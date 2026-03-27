#include <stdio.h>
#include <string.h>

int main(void) {
  int iVar1;
  char local_7e [14];
  char local_70 [100];
  int local_c;
  
  local_c = 0;
  local_7e[0] = '_';
  local_7e[1] = '_';
  local_7e[2] = 's';
  local_7e[3] = 't';
  local_7e[4] = 'a';
  local_7e[5] = 'c';
  local_7e[6] = 'k';
  local_7e[7] = '_';
  local_7e[8] = 'c';
  local_7e[9] = 'h';
  local_7e[10] = 'e';
  local_7e[11] = 'c';
  local_7e[12] = 'k';
  local_7e[13] = '\0';
  printf("Please enter key: ");
  scanf("%23s", local_70);
  iVar1 = strcmp(local_70,local_7e);
  if (iVar1 == 0) {
    printf("Good job.\n");
  }
  else {
    printf("Nope.\n");
  }
  return 0;
}