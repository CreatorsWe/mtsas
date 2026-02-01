#include <iostream>
#include <cstdlib>

void integerOverflowVulnerability() {
    int size, count;
    std::cout << "Enter the number of elements: ";
    std::cin >> count;

    // 攻击者可能传入一个极大的值，使得 size * sizeof(int) 发生整数溢出
    size = count * sizeof(int);
    // 例如：count = 1073741824, sizeof(int)=4, 则 size = 1073741824 * 4 = 4294967296
    // 在32位系统上，4294967296 会溢出为 0[6](@ref)
    std::cout << "Attempting to allocate " << size << " bytes..." << std::endl;

    int* array = (int*)malloc(size); // 如果size为0或很小，只会分配很小的缓冲区
    if (array == NULL) {
        std::cerr << "Memory allocation failed!" << std::endl;
        return;
    }

    // 但循环仍然按照巨大的 count 值进行写入，导致严重的堆溢出
    for (int i = 0; i < count; i++) {
        array[i] = i; // 当 i >= (真实分配的大小 / sizeof(int)) 时，发生越界写
    }

    free(array);
}

int main() {
    integerOverflowVulnerability();
    return 0;
}
