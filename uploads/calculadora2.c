#include <stdio.h>
#include <string.h>

int soma(int a, int b) {
    return a + b;
}

int multiplica(int a, int b) {
    return a * b;
}

int main() {
    int a = 20;
    int b = 3;

    printf("Calculadora v2");
    printf("Soma: %d\n", soma(a, b));
    printf("Multiplicacao: %d\n", multiplica(a, b));

    return 0;
}