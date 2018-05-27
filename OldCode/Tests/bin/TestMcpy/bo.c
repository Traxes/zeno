#include <stdio.h>

int vuln(){
    char form[2048];
    char bad[1024];
    int n;
    fgets(form, 2047, stdin);
    n = strlen(form);
    memcpy(bad, form, n);
    printf("bad = %s\n", bad);
    return 1;
}


void notvuln(){
    return;
}


int main(int argc, char const *argv[])
{
    char buf[21];
    for(;;)
    {
        vuln();
    }
    
    return 0;
}

