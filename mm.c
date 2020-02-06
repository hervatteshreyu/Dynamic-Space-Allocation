/*
 * mm.c
 *
 * Name: Shreyas Hervatte Santosh
 *
 *This is a basic implementation of malloc. Throughput and utilization are not being accounted for.
 *This version only aims for correctness of malloc. 
 *Malloc works by increasing the size of the heap everytime malloc is called.
 *It maintains 16 byte alignment of payload addresses by starting off with some padding before the prologue
 *and every malloc returns 16 byte aligned addresses and adds a header and a footer of 8 bytes each
 *
 *Free does essentially nothing but clear the allocated bit of the header of the pointer it receives
 *
 *Realloc simply mallocs and copies the data from the old block.
 *
 *Since malloc and realloc aren't looking for free blocks and since free isn't coelescing free blocks,
 *This model has very bad memory utilization.
 *However due to simple design of malloc, realloc and free, the throughput is higher than the benchmark
 *
 *In further checkpoints, explicit and segregated free list models will be explored to improve utilization and throughput
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

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}

/*Pointer keeping track of the Head of the free heap*/                                                                                void * head = NULL;

/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    /*start is a long pointer - 8bytes long*/
    /*Adding 1 will move the address forward by 8 bytes*/
    long * start = (long*)mem_sbrk((intptr_t)24);

    /*Return false for initialization errors*/
    if (start == NULL)return false;

    /*Calculate lower 4 bytes of address including 2 headers and a footer*/
    int offset = (intptr_t)(start+3) & 0xF;

    if(offset != 0){
        /*Not 16 byte aligned - add padding before prologue*/
        /*Payload after prologue + header will be 16 byte aligned*/
        start = start+((0x10-offset)/8);
    }

    /*Header of Prologue*/
    /*Set size 0 and alloc bit high*/
    *start = *start & 0x0;
    *start = *start | 0x1;
    start = start + 1;

    /*Footer of Prologue*/
    /*Set size 0 and alloc bit high*/
    *start = *start & 0x0;                                                                                                                *start = *start | 0x1;
    start = start + 1;

    /*Header of Epilogue*/
    /*Set size 0 and alloc bit high*/
    *start = *start & 0x0;
    *start = *start | 0x1;
    start = start + 1;
    
    /*Global head points to address after prologue + header*/
    head = (void *) start;

    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    
    if(size>0){
        
        /*Extend heap by 16byte aligned size + 16 bytes for header and footer*/
        /*Store return value for pointer to check for errors with mem_sbrk*/
        void *temp_head = mem_sbrk((intptr_t)(align(size)+16));
        if (temp_head == (void *)-1)return NULL;

        /*New payload will start from global head - header has already been allocated*/
        void * ret_ptr = head;

        /*Adjust the locations of the payload header, footer and new epilogue*/
        char * header=head-8, *footer = mem_heap_hi()-7, *epilogue = mem_heap_hi()+1;

        /*Store size in header and set allocated bit*/
        /*Typecasting to (long *) makes sure all 8 bytes of the  header are being used*/
        *(long*)header = align(size);
        *(long*)header = *(long*)header | 0x1;
        
        /*Store size in footer and set allocated bit*/
        /*Typecasting to (long *) makes sure all 8 bytes of the  header are being used*/
        *(long*)footer = align(size);
        *(long*)footer = *(long*)footer | 0x1;

        /*Set empty epilogue and set allocated bit*/
        /*Typecasting to (long *) makes sure all 8 bytes of the  header are being used*/
        *(long*)epilogue = *(long*)epilogue & 0x0;
        *(long*)epilogue = *(long*)epilogue | 0x1;

        /*Global head points to end of allocated payload + header of next payload*/
        head = (void *)((long*)epilogue+1);

        return ret_ptr;
    }
    /* Return NULL if size<=0 */
    return NULL;
}

/*
 * free
 */
void free(void* ptr)
{
    /*Alloc bit of header is cleared*/
    *((char *)ptr-8) = *((char *)ptr-8) & 0xfffffffffffffff0;
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    /*If size is zero, return NULL - Undefined behaviour*/
    if(size == 0)return NULL;

    /*Try to malloc for a new size*/
    void * newptr = malloc(size);

    /*Malloc error*/
    if(newptr == NULL)return NULL;

    /*If old pointer wsan't returned from a malloc or calloc, return output of malloc*/
    if(oldptr == NULL)return newptr;

    /*Read size of old block*/
    /*Dereferencing (long*) gives 8 byte value*/
    size_t oldsize = *((long*)oldptr-1);
    oldsize = (oldsize & 0xfffffffffffffff0);

    /*Align new size to 16 bytes*/
    size = align(size);

    /*Copy data from old block to new block - size decided by minimum of old and new sizes*/
    mem_memcpy(newptr, oldptr, oldsize>size?size:oldsize);
    
    return newptr;
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
    /* NOT IMPLEMENTED IN THIS CHECKPOINT */
#endif /* DEBUG */
    return true;
}
