#include <stdio.h>

int vuln(){
    char form[2048];
    char bad[1024];
    fgets(form, 2047, stdin);
    memcpy(bad, form, sizeof(form));
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
        if(strcmp("vuln\n", buf) == 0){
            vuln();  
            continue;       
        }
 
    }
    
    return 0;
}

