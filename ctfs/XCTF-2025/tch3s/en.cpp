#include <iostream>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <dlfcn.h>
#include <unistd.h>
using namespace std;

typedef void (*derived_key_func)(char *, char *);
typedef void (*tchar_encrypt_func)(char *, char *, char *);
typedef void (*tchar_decrypt_func)(char *, char *, char *);

int main()
{
    void *handler = dlopen("./tchar.so", RTLD_LAZY);
    if (!handler)
    {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return 1;
    }
    derived_key_func derived_key = (derived_key_func)dlsym(handler, "derive_key");
    tchar_encrypt_func tchar_encrypt = (tchar_encrypt_func)dlsym(handler, "encrypt");
    tchar_decrypt_func tchar_decrypt = (tchar_decrypt_func)dlsym(handler, "decrypt");

    char key[16];
    memset(key, 0, 16);

    char round_keys_test[512];
    derived_key(round_keys_test, key);

    cout << "Round keys" << endl;
    for (int i = 0; i < 13 * 16; ++i)
    {
        printf("%02x ", (unsigned char)round_keys_test[i]);
    }
    printf("\n");
}
