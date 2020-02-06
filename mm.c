/*
 * mm.c
 *
 * Name: Shreyas Hervatte Santosh
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 * Also, read malloclab.pdf carefully and in its entirety before beginning.
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want to enable your debugging output and heap checker code,
 * uncomment the following line. Be sure not to have debugging enabled
 * in your final submission.
 */
// #define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16

/*Pointer keeping track of the Head of the free heap*/
void * head = NULL;
/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    /* IMPLEMENT THIS */
    long * start = (long*)mem_sbrk((intptr_t)24);
    printf("Heap starts at %p\n and ends at %p\n",start,mem_heap_hi());
    int offset = (intptr_t)(start+3) & 0xF;
    printf("Offset after adding prologue and header - 0x%x\n",offset);
    if(offset != 0){
        //Not 16 byte aligned - add padding before prologue
        start = start+((0x10-offset)/8);
        printf("Heap start after adjusting offset - %p\n Malloc will start from %p",start,start+3);
    }
    printf("%ld\n",*start);
    *start = *start & 0x0;
    *start = *start | 0x1;
    printf("Header - %ld\nHeader size - %ld\n",*start,sizeof(*start));
    start = start + 1;
    *start = *start & 0x0;                                                                                                                *start = *start | 0x1;
    printf("Footer added at %p\nFooter - %ld\nFooter size - %ld\n",start,*start,sizeof(*start));
    start = start + 1;
    *start = *start & 0x0;
    *start = *start | 0x1;
    printf("Header added at %p\nHeader - %ld\nHeader size - %ld\n",start,*start,sizeof(*start));
    start = start + 1;
    printf("Heap after prologue and new header %p\n",(void *)start -1 );
    head = (void *) start;
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    if(size>0){
        void * ret_ptr = mem_sbrk((intptr_t)align(size));
        
        if (ret_ptr == (void *)-1)return NULL;
        return ret_ptr;
    }
    /* IMPLEMENT THIS */
    return NULL;
}

/*
 * free
 */
void free(void* ptr)
{
    /* IMPLEMENT THIS */
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    /* IMPLEMENT THIS */
    return NULL;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ptr;
    size *= nmemb;
    ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

/*
 * Returns whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Returns whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
#ifdef DEBUG
    /* Write code to check heap invariants here */
    /* IMPLEMENT THIS */
#endif /* DEBUG */
    return true;
}
