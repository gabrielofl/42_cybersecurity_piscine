int main(void) {
    char input[24];
    char decoded[9];

    printf("Please enter key: ");
    if (scanf("%23s", input) != 1)
        fail();

    if (input[0] != '4' || input[1] != '2')
        fail();

    memset(decoded, 0, sizeof(decoded));
    decoded[0] = '*';   // ASCII 42

    int i = 2;
    int out = 1;

    while (strlen(decoded) < 8 && i < strlen(input)) {
        decoded[out] = (char)atoi(&input[i]);
        i += 3;
        out++;
    }
    decoded[out] = '\0';

    if (strcmp(decoded, TARGET_STRING) == 0)
        success();
    else
        fail();
}