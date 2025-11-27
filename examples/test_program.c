#include <stdio.h>

int main() {
    printf("Hello, Binary Visualizer!\n");
    
    // Add some variety to the binary
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i * i;
    }
    
    printf("Sum: %d\n", sum);
    return 0;
}
