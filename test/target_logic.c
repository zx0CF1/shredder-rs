// Compilar con: cl /Fe:test/test_target.exe test/target_logic.c /link /DYNAMICBASE:NO /FIXED
// Este código no usa la librería estándar para evitar problemas de RIP-relative en strings.
int main() {
    int a = 5;
    int b = 10;
    int result = 0;

    // Un bucle añade complejidad al Control Flow Graph
    for(int i = 0; i < 5; i++) {
        result += (a * i) + b;
    }

    // Resultado esperado: 
    // i=0: 0+10 = 10
    // i=1: 5+10 = 15
    // i=2: 10+10 = 20
    // i=3: 15+10 = 25
    // i=4: 20+10 = 30
    // Total: 10+15+20+25+30 = 100
    return result; 
}