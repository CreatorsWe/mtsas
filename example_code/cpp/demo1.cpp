#include <iostream>

class Base {
public:
    virtual void speak() {
        std::cout << "I am Base." << std::endl;
    }
    int base_data = 10;
};

class Derived : public Base {
public:
    void speak() override {
        std::cout << "I am Derived." << std::endl;
    }
    int derived_secret = 42; // 这是一个敏感数据
};

void typeConfusionAttack(Base* obj) {
    // 假设这里由于逻辑错误或恶意攻击，我们确信obj指向的是Derived对象
    // 但实际上它可能只是一个Base对象
    Derived* derivedPtr = static_cast<Derived*>(obj); // 不安全的向下转型
    // 如果obj实际上不是Derived，那么以下访问将越界
    std::cout << "Secret is: " << derivedPtr->derived_secret << std::endl; // 未定义行为！[8](@ref)
}

int main() {
    Base base_obj;
    // 错误地传入一个Base对象，而非Derived对象
    typeConfusionAttack(&base_obj); // 这将导致derivedPtr->derived_secret访问到未知内存

    // 正确的情况
    // Derived derived_obj;
    // typeConfusionAttack(&derived_obj); // 这会正常工作

    return 0;
}
