#include<iostream>
#include<string>
int main(){
    char*p="abcd";
    //std::cout<<p;
    char **p1=&p;
    char ***p2=&p1;
    char ***p3=&p1;
    std::cout<<p2;
    std::cout<<"\n";
    std::cout<<p3;
    std::cout<<"\n";
    p2++;
    std::cout<<p2;
    std::cout<<"\n";
    std::cout<<p3;
    std::cout<<"\n";
    std::cout << (reinterpret_cast<char*>(p2) - reinterpret_cast<char*>(p3)) << std::endl;
}