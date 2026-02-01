#include <iostream>

void danglingPointerDemo() {
    int* ptr = new int(100); // 动态分配内存
    std::cout << "Initial value: " << *ptr << std::endl;

    delete ptr; // 释放内存，此时ptr变成"悬垂指针"
    // 但编译器或程序员可能未将ptr置为nullptr

    // 再次使用悬垂指针，行为未定义！
    // 可能正常输出100（内存还未被覆盖），也可能输出乱码，或导致程序崩溃[8](@ref)
    std::cout << "Value after deletion (dangling read): " << *ptr << std::endl;

    // 更危险的是尝试写入
    *ptr = 200; // 可能破坏该地址现在已被分配用作他用的数据
    std::cout << "Value after rewriting: " << *ptr << std::endl;
}

int main() {
    danglingPointerDemo();
    return 0;
}
