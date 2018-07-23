#include <stdio.h>

int main ()
{
  char str [10];
  char test [50];
  int i;
  int x;

  printf ("Enter Stuff (i, str, i): ");
  scanf ("%d%79s%x",&i,str,&x); 
  scanf ("%49s", test); 
  
  printf ("You have entered %s %#x (%d).\n",str,x,i);
  
  return 0;
}