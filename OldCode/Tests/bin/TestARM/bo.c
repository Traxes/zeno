#include <stdio.h>

void vuln1(){
  char str [10];
  char test [50];
  int i;
  int x;

  printf ("Enter Stuff (i, str, i): ");
  scanf ("%d%79s%x",&i,str,&x); 
  scanf ("%s", test); 
  
  printf ("You have entered %s %#x (%d).\n",str,x,i);
}

int vuln2(){
  char form[2048];
  char bad[1024];
  fgets(form, 2047, stdin);
  memcpy(bad, form, 2047);
  printf("bad = %s\n", bad);
  return 1;
}

int vuln3(){
  char form[2048];
  char bad[1024];
  fgets(form, 2049, stdin);
  memcpy(bad, form, 2047);
  printf("bad = %s\n", bad);
  return 1;
}

void vuln4(){
  char str[50];
  printf("Enter a string : ");
  gets(str);
  printf("You entered: %s", str);
  return(0);
}

int vuln5(){
  char form[2048];
  char bad[1024];
  fgets(form, 2047, stdin);
  memcpy(bad, form, sizeof(form));
  return 1;
}

int vuln6(){
  char form[2048];
  char bad[1024];
  fgets(form, 2049, stdin);
  strcpy(bad, form);
  printf("bad = %s\n", bad);
  return 1;
}

int vuln7(){
  char form[2048];
  char bad[1024];
  fgets(form, 2049, stdin);
  strncpy(bad, form, sizeof(form));
  printf("bad = %s\n", bad);
  return 1;
}

int vuln8(){
  char form[2048];
  char bad[1024];
  fgets(form, 2048, stdin);
  strcat(bad, form);
  printf("bad = %s\n", bad);
  return 1;
}

int vuln9(){
  char form[2048];
  char bad[1024];
  fgets(form, 2049, stdin);
  sprintf(bad, "This is the input %s", form);
  printf("bad = %s\n", bad);
  return 1;
}

int vuln10(){
  char str [10];
  int i;
  int x;

  printf ("Enter Stuff (i, str, i): ");
  scanf ("%d%79s%x",&i,str,&x);

  printf ("You have entered %s %#x (%d).\n",str,x,i);

  return 0;
}

void vuln11(){
  char test [50];
  int i;
  int x;

  printf ("Enter Stuff (str): ");
  scanf ("%s", test);

  printf ("You have entered %s\n",test);

  return 0;
}

void not_vuln1(){
  char str [80];
  int i;
  int x;

  printf ("Enter Stuff (i, str, i): ");
  scanf ("%d%79s%x",&i,str,&x);

  printf ("You have entered %s %#x (%d).\n",str,x,i);

  return 0;
}

int main ()
{
  vuln1();
  vuln2();
  vuln3();
  vuln4();
  vuln5();
  vuln6();
  vuln7();
  vuln8();
  vuln9();
  vuln10();
  vuln11();

  not_vuln1();

  return 0;
}