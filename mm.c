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

    int offset = (intptr_t)(start+3) & 0xF;

    if(offset != 0){
        //Not 16 byte aligned - add padding before prologue
        start = start+((0x10-offset)/8);

    }
    /*Header of Prologue*/
    *start = *start & 0x0;
    *start = *start | 0x1;
    start = start + 1;
    /*Footer of Prologue*/
    *start = *start & 0x0;                                                                                                                *start = *start | 0x1;
    start = start + 1;
    /*Header of Epilogue*/
    *start = *start & 0x0;
    *start = *start | 0x1;
    start = start + 1;
    head = (void *) start;
    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    #ifdef DEBUG
    printf("++++++++++Inside Malloc++++++++++\nSize to allocate %ld\n",size);
    #endif
    if(size>0){
        //        printf("Size %ld\nSize+footer %ld\n",size,size+8);
        void *temp_head = mem_sbrk((intptr_t)(align(size)+16));
        if (temp_head == (void *)-1)return NULL;
        void * ret_ptr = head;
        char * header=head-8, *footer = mem_heap_hi()-7, *epilogue = mem_heap_hi()+1;
        *(long*)header = align(size);
        *(long*)header = *(long*)header | 0x1;
        *(long*)footer = align(size);                                                                                                                *(long*)footer = *(long*)footer | 0x1;
        *(long*)epilogue = *(long*)epilogue & 0x0;
        *(long*)epilogue = *(long*)epilogue | 0x1;
        head = (void *)((long*)epilogue+1);
        #ifdef DEBUG
        printf("%ld bytes Allocated at %p\n",*(long*)header,ret_ptr);
        #endif
        //printf("Retptr%p\nHeader%p\nFooter%p\nEpilogue%p\nNewHead%p\n",ret_ptr,header,footer,epilogue,head);
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
    *((char *)ptr-8) = *((char *)ptr-8) & 0xfffffffffffffff0;
    /* IMPLEMENT THIS */
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    #ifdef DEBUG
    printf("====Inside Realloc====\nOldptr %p\n Size %ld\n",oldptr,size);
    printf("Heap end before malloc %p\n",mem_heap_hi());
    #endif
    void * newptr = malloc(size);
    #ifdef DEBUG
    printf("Heap end after malloc %p\n",mem_heap_hi());
    printf("Newptr %p\n",newptr);
    #endif
    if(newptr == NULL)return NULL;
    if(oldptr == NULL)return newptr;
    if(size == 0)return NULL;
    size_t oldsize = *((long*)oldptr-1);
    #ifdef DEBUG
    printf("Oldsize 0x%lx\n",oldsize);
    printf("Oldsize %lu\n",oldsize);
    #endif
    oldsize = (oldsize & 0xfffffffffffffff0);
    #ifdef DEBUG
    printf("Oldsize masked 0x%lx\n",oldsize);
    printf("Oldsize masked %lu\n",oldsize);
    printf("Newsize %ld\n",size);
    #endif
    size = align(size);
    #ifdef DEBUG
    printf("New size aligned %ld\n",size);
    #endif
    mem_memcpy(newptr, oldptr, oldsize>size?size:oldsize);
    return newptr;
    /* IMPLEMENT THIS */
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
