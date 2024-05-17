#ifndef FIXED_POINT_H
#define FIXED_POINT_H
#include<ctype.h>
#include<stdio.h>
typedef int FP;
extern const int f_const = 1<<14;

int int_to_fp (int n);
int fp_to_int_round (int x);
int fp_to_int (int x);
int add_fp (int x, int y);
int add_mixed (int x, int n);
int sub_fp (int x, int y);
int sub_mixed (int x, int n);
int mult_fp (int x, int y);
int mult_mixed (int x, int y);
int div_fp (int x, int y);
int div_mixed (int x, int n);
#endif