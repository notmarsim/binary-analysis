#include <stdio.h>
#include <string.h>

int soma(int a, int b) {
    return a + b;
}

int multiplica(int a, int b) {
    return a * b;
}

int main() {
    int a = 15;
    int b = 7;

    printf("Calculadora v1");
    printf("Soma: %d\n", soma(a, b));
    printf("Multiplicacao: %d\n", multiplica(a, b));

    return 0;
}