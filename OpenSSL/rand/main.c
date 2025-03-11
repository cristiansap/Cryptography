#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hex_or(unsigned char *rand1, unsigned char *rand2, unsigned char *result);
void hex_and(unsigned char *rand1, unsigned char *rand2, unsigned char *result);
void hex_xor(unsigned char *k1, unsigned char *k2, unsigned char *result);

int main(void) {
    unsigned char *rand1 = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
    unsigned char *rand2 = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    // Dynamic allocation of k1, k2, key
    unsigned char *k1 = (unsigned char *) malloc((strlen(rand1)+1) * sizeof(unsigned char));   // +1 for the trail character '\0'
    unsigned char *k2 = (unsigned char *) malloc((strlen(rand1)+1) * sizeof(unsigned char));
    unsigned char *key = (unsigned char *) malloc((strlen(rand1)+1) * sizeof(unsigned char));

    hex_or(rand1, rand2, k1);
    printf("\nk1: %s", k1);

    hex_and(rand1, rand2, k2);
    printf("\nk2: %s", k2);

    hex_xor(k1, k2, key);
    printf("\nkey: %s\n", key);

    return 0;
}

void hex_or(unsigned char *rand1, unsigned char *rand2, unsigned char *result) {
    unsigned int num1, num2, res;
    int index = 0, max_iter = strlen(rand1);

    while (index < max_iter) {
        // Read one byte (i.e. 2 hex characters)
        sscanf(rand1, "%2x", &num1);
        sscanf(rand2, "%2x", &num2);

        // OR operation
        res = num1 | num2;

        // Append the result to the output string
        sprintf(result + index, "%02x", res);
        index += 2;
        if (index + 1 < max_iter) {
            // Append the dash to the output string
            sprintf(result + index, "-");
            index += 1;
        }

        // Move to the next byte (2 characters + 1 dash)
        rand1 += 3;
        rand2 += 3;
    }
    result[index] = '\0';
}

void hex_and(unsigned char *rand1, unsigned char *rand2, unsigned char *result) {
    unsigned int num1, num2, res;
    int index = 0, max_iter = strlen(rand1);

    while (index < max_iter) {
        // Read one byte (i.e. 2 hex characters)
        sscanf(rand1, "%2x", &num1);
        sscanf(rand2, "%2x", &num2);

        // AND operation
        res = num1 & num2;

        // Append the result to the output string
        sprintf(result + index, "%02x", res);
        index += 2;
        if (index + 1 < max_iter) {
            // Append the dash to the output string
            sprintf(result + index, "-");
            index += 1;
        }

        // Move to the next byte (2 characters + 1 dash)
        rand1 += 3;
        rand2 += 3;
    }
    result[index] = '\0';
}

void hex_xor(unsigned char *k1, unsigned char *k2, unsigned char *result) {
    unsigned int num1, num2, res;
    int index = 0, max_iter = strlen(k1);

    while (index < max_iter) {
        // Read one byte (i.e. 2 hex characters)
        sscanf(k1, "%2x", &num1);
        sscanf(k2, "%2x", &num2);

        // XOR operation
        res = num1 ^ num2;

        // Append the result to the output string
        sprintf(result + index, "%02x", res);
        index += 2;
        if (index + 1 < max_iter) {
            // Append the dash to the output string
            sprintf(result + index, "-");
            index += 1;
        }

        // Move to the next byte (2 characters + 1 dash)
        k1 += 3;
        k2 += 3;
    }
    result[index] = '\0';
}