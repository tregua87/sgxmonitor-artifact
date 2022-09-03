#include <stdio.h>
#include <stdlib.h> 
#include <time.h> 

void quicksort(int number[25],int first,int last) {
    int i, j, pivot, temp;
    if(first<last) {
        pivot=first;
        i=first;
        j=last;
        while(i<j) {
            while(number[i]<=number[pivot]&&i<last) i++;

            while(number[j]>number[pivot]) j--;

            if(i<j) {
                temp=number[i];
                number[i]=number[j];
                number[j]=temp;
            }
        }

        temp=number[pivot];
        number[pivot]=number[j];
        number[j]=temp;
        quicksort(number,first,j-1);
        quicksort(number,j+1,last);
    }
}

int main() {
#define MAX_ELEMENT 1000
    int i, number[MAX_ELEMENT];

    srand(time(0));
    int upper = 100;
    int lower = 0;
    for (i = 0; i < MAX_ELEMENT; i++) { 
        int num = (rand() % (upper - lower + 1)) + lower; 
        number[i] = num;
    } 

    printf("The Unsorted list is:\n");
    for(i = 0; i < MAX_ELEMENT; i++)
        printf(" %d",number[i]);

    quicksort(number,0,MAX_ELEMENT-1);

    printf("\nThe Sorted Order is:\n");
    for(i=0;i<MAX_ELEMENT;i++)
        printf(" %d",number[i]);

    return 0;
}