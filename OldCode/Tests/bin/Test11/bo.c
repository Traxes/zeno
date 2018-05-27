#include <stdio.h>

int main ()
{
  char str [10];
  int i;
  int x;

  printf ("Enter Stuff (i, str, i): ");
  scanf ("%d%79s%x",&i,str,&x);  
  
  printf ("You have entered %s %#x (%d).\n",str,x,i);
  
  return 0;
}