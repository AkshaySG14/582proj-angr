#include <iostream>
#include <string>

using std::endl;
using std::cout;

static int boo = 5, goo = 19, doo = 21;

int main(int argc, char **argv)
{
    
    cout << "Hello World" << endl;
    int test = std::stoi(argv[1]);
    int length = std::stoi(argv[2]);
    if (argc < 2) {
        cout << "Error" << endl;
        exit(1);
    }
    if (test > 0) {
        for (int i = 0; i < length; ++i) {
            cout << i << endl;
        }
        cout << "Test" << endl;
    } else {
        cout << "Second Branch" << endl;
    }
    return 0;
}