#include <stdio.h>
#include <string.h>

int vuln(int n){
    char form[2048];
    char bad[1024];
    fgets(form, 2049, stdin);
    strncpy(bad, form, sizeof(form));
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
        fgets(buf, 20, stdin);
        vuln(atoi(buf));
    }
    
    return 0;
}

