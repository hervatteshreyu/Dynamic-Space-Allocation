/*
 * mm.c
 *
 * Name: Shreyas Hervatte Santosh
 *
 *Note to self - MAKE A COUNTER TO SEE SIZE CLASSES ALONG WITH FREQUENCY OF MALLOC CALLS
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

#define CLASS0 16
#define CLASS1 32
#define CLASS2 48 
#define CLASS3 64
#define CLASS4 128
#define CLASS5 512
#define CLASS6 1024
#define CLASS7 2048
#define CLASS8 4096
#define CLASS9 16384
#define CLASS10 65536
#define CLASS11 262144
#define CLASS12 1048576
#define CLASS13 4194304
#define CLASS14 16777216
#define CLASS15 67108864
/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}


/**********************LINKED LIST*********************/
typedef struct FreeListNode_s {
    struct FreeListNode_s * prev;
    struct FreeListNode_s * next;
}FreeListNode;

FreeListNode * freelist[16];

void add_free_node(FreeListNode ** head, FreeListNode * node){
    if(*head == NULL){
        *head = node;
        node->next = NULL;
        node->prev = NULL;
    }
    else{
    node->next = *head;
    node->prev = NULL;
    (*head)->prev = node;
    *head = node;
    }
}

FreeListNode* remove_free_node(FreeListNode ** head, FreeListNode * node)
{
    FreeListNode* removed_node = node;
    if(*head == node){
        (*head) = (node->next);
    }
    else{
        node->prev->next = node->next;
    }
    if(node->next!=NULL)node->next->prev = node->prev;
    return removed_node;
}    
bool list_at_end(FreeListNode * node)
{
    if(node->next == NULL)
        return true;
    else
        return false;
}

int size_to_class_index(size_t size){
    if (size == CLASS0) return 0;
    if (size >CLASS0 && size <=CLASS1) return 1;
    if (size >CLASS1 && size <=CLASS2) return 2;
    if (size >CLASS2 && size <=CLASS3) return 3;
    if (size >CLASS3 && size <=CLASS4) return 4;
    if (size >CLASS4 && size <=CLASS5) return 5;
    if (size >CLASS5 && size <=CLASS6) return 6;
    if (size >CLASS6 && size <=CLASS7) return 7;
    if (size >CLASS7 && size <=CLASS8) return 8;
    if (size >CLASS8 && size <=CLASS9) return 9;
    if (size >CLASS9 && size <=CLASS10) return 10;
    if (size >CLASS10 && size <=CLASS11) return 11;
    if (size >CLASS11 && size <=CLASS12) return 12;
    if (size >CLASS12 && size <=CLASS13) return 13;
    if (size >CLASS13 && size <=CLASS14) return 14;
    if (size >CLASS14 && size <=CLASS15) return 15;
    return -1;
}

size_t get_size_from_header(void * ptr){
    long * header =  ((long *)ptr )-1;
    size_t size = *header & ~0xf;
    return size;
}
void set_header_free(void * ptr){
    long * header = ((long *)ptr-1); 
    *header = *header & ~0xf;
}
void set_alloc(void * ptr){
    long * header = (((long *)ptr)-1);
    *header = *header & ~0xf;
    long * footer = (((long *)ptr) + ((*header)/8));
    *header = *header + 1;
    *footer = *header;
}
bool is_free_left(void * ptr){
    long * footer = (((long *)ptr)-2);
    if(((*footer) & 0xf) == 1)return false;
    return true;
}
bool is_free_right(void * ptr){
    long * header = (((long *)ptr)-1);
    *header = *header & ~0xf;
    long * footer = (((long *)ptr) + ((*header)/8));
    long * next_header = footer + 1;
    if(((*next_header) & 0xf) == 1)return false;
    return true;
}
void coalesce_right(void * ptr){
    if(!is_free_right(ptr))return;
    else{
    long * header = (((long *)ptr)-1);
    long * footer = (((long *)ptr) + ((*header)/8));
    long * next_header = footer + 1;
    long * next_footer = (((long *)ptr) + ((*next_header)/8));
    size_t size = next_footer - header + 1;
    *header = size;
    *next_footer = size;
    return;
    }
}

size_t size_of_node(FreeListNode * node){
    return get_size_from_header((void *) node);
}
void split_block(FreeListNode * node, size_t size, size_t blocksize){
    size_t newsize = blocksize - size-16;
    void * header =(void*) (((long *) node) - 1);
    *(long *)header = size+1;
    void * end_of_block = (void *) (((long *)node) + (size/8));
    *(long *)end_of_block = size+1;
    end_of_block = end_of_block + 8;
    *(long *)end_of_block = newsize;
    void * start_of_block = end_of_block + 8;
    end_of_block = start_of_block + newsize;
    *(long *)end_of_block = newsize;
    //    int index = size_to_class_index(newsize);
    // add_free_node(&freelist[index], (FreeListNode *) start_of_block);
    free(start_of_block);
}
/*
 * Initialize: returns false on error, true on success.
 */
bool mm_init(void)
{
    for(int i=0;i<16;i++){
        freelist[i]=NULL;
    }
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
    //    head = (void *) start;

    return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    
    if(size<=0)return NULL;
    char * ret_ptr = NULL;
    size = align(size);
    bool split_flag=false, found_flag=false;
    int index = size_to_class_index(size);
    size_t blocksize = 0;
    if(index!=-1){
        if(freelist[index]!=NULL){
            FreeListNode * node = freelist[index];
            while(!list_at_end(node)){
                blocksize = size_of_node(node);
                if(size==blocksize){
                    found_flag=true;
                    break;
                }
                if(size<blocksize-32){
                    found_flag=true;
                    split_flag=true;
                    break;
                }
                node=node->next;
            }
            if(found_flag){
                if(split_flag){
                    split_block(node, size,blocksize);
                }
                ret_ptr = (char *)remove_free_node( &freelist[index] , node);
                set_alloc((void *)ret_ptr);
                return (void *)ret_ptr;
            }
        }
        
    }
    
    ret_ptr = mem_heap_hi() + 9;
    void *temp_head = mem_sbrk((intptr_t)(size+16));
    if (temp_head == (void *)-1)return NULL;
    
    char * header=(char *)((long *)ret_ptr - 1), *footer = mem_heap_hi()-7, *epilogue = mem_heap_hi()+1;
    
    *(long*)header = size+1;
    
    *(long*)footer = size+1;
    
    *(long*)epilogue = (*(long*)epilogue & 0x0)+1;
    set_alloc((void *)ret_ptr);
    return (void *) ret_ptr;
}

/*
 * free
 */
void free(void* ptr)
{
    size_t size = get_size_from_header(ptr);
    /*Alloc bit of header is cleared*/
    set_header_free(ptr);
    //    coalesce_right(ptr);
    int index = size_to_class_index(size);
    add_free_node(&freelist[index], (FreeListNode *) ptr);
    return;
}

/*
 * realloc
 */
void* realloc(void* oldptr, size_t size)
{
    /*If size is zero, return NULL - Undefined behaviour*/
    if(size == 0){
        free(oldptr);
        return NULL;
    }

    /*Try to malloc for a new size*/
    void * newptr = malloc(size);

    /*Malloc error*/
    if(newptr == NULL)return NULL;

    /*If old pointer wsan't returned from a malloc or calloc, return output of malloc*/
    if(oldptr == NULL)return newptr;

    /*Read size of old block*/
    /*Dereferencing (long*) gives 8 byte value*/
    size_t oldsize = *((long*)oldptr-1);
    oldsize = (oldsize & ~0xf);
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
