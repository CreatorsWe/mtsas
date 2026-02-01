#include <iostream>
#include <cstring>

void heapBufferOverflow() {
    const int SIZE = 64;
    char* buffer = new char[SIZE]; // 在堆上动态分配内存
    std::cout << "Enter input: ";
    // 假设我们从不可信的源（如网络）获取数据
    char large_input[1000];
    std::cin.getline(large_input, 1000);

    // 危险！未检查输入长度就进行复制
    strcpy(buffer, large_input); // 如果large_input长度超过64字节，将破坏堆内存结构[7](@ref)
    std::cout << "Buffer: " << buffer << std::endl;

    delete[] buffer;
}

int main() {
    heapBufferOverflow();
    return 0;
}
