#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include "mem.h"

/*
 * This structure serves as the header for each allocated and free block
 * It also serves as the footer for each free block
 * The blocks are ordered in the increasing order of addresses 
 */
typedef struct block_tag{

  int size_status;
  
 /*
  * Size of the block is always a multiple of 4
  * => last two bits are always zero - can be used to store other information
  *
  * LSB -> Least Significant Bit (Last Bit)
  * SLB -> Second Last Bit 
  * LSB = 0 => free block
  * LSB = 1 => allocated/busy block
  * SLB = 0 => previous block is free
  * SLB = 1 => previous block is allocated/busy
  * 
  * When used as the footer the last two bits should be zero
  */

 /*
  * Examples:
  * 
  * For a busy block with a payload of 24 bytes (i.e. 24 bytes data + an additional 4 bytes for header)
  * Header:
  * If the previous block is allocated, size_status should be set to 31
  * If the previous block is free, size_status should be set to 29
  * 
  * For a free block of size 28 bytes (including 4 bytes for header + 4 bytes for footer)
  * Header:
  * If the previous block is allocated, size_status should be set to 30
  * If the previous block is free, size_status should be set to 28
  * Footer:
  * size_status should be 28
  * 
  */

} block_tag;

/* Global variable - This will always point to the first block
 * i.e. the block with the lowest address */
block_tag *first_block = NULL;

/* Global variable - Total available memory */
int total_mem_size = 0;

/* 
 * Function for allocating 'size' bytes
 * Returns address of the payload in the allocated block on success 
 * Returns NULL on failure 
 * Here is what this function should accomplish 
 * - If size is less than equal to 0 - Return NULL
 * - Round up size to a multiple of 4 
 * - Traverse the list of blocks and allocate the best free block which can accommodate the requested size 
 * - Also, when allocating a block - split it into two blocks when possible 
 * Tips: Be careful with pointer arithmetic 
 */
void* Mem_Alloc(int size){
	/* Your code goes in here */
    if(size == 0 || size < -1)
        return NULL;
    if(size % 4 != 0)
        size = size - size % 4 + 4;//round up size if size is not the multiple of 4
    block_tag *last_block = NULL;
    block_tag *current_block = NULL;
    block_tag *best_block = NULL;
    current_block = first_block;
    last_block = (block_tag*)((char*)first_block + total_mem_size - 8);//set a pointer at the location that 8 btyes away from the end
    while(current_block < last_block || current_block == last_block)//loop to find the best fit block. We assume every empty block block we find is the best and compare to the next. If the next is fit and smaller than the previous best, then assign the current next as best
    {
        if((current_block -> size_status & 1) == 0 && (current_block -> size_status & ~3) >= (size + 4) )
        {
            if(best_block ==  NULL)
                best_block = current_block;
            else if((best_block -> size_status & ~3) > (current_block -> size_status & ~3))
                best_block = current_block;
        }
        current_block = (block_tag*)((char*)current_block + (current_block -> size_status & ~3));
    }
    if(best_block == NULL)//if best_block is NULL, the allocation is not successful then we return NULL
    {
        Mem_Dump();
        return NULL;
    }
    if(((best_block -> size_status & ~3) - size - 4) > 8 || ((best_block -> size_status & ~3) - size - 4) == 8 )//if the best block can be split, then we modify the status of spilt block
    {
        block_tag *split_block_h = (block_tag*)((char*)best_block + size + 4);
        split_block_h -> size_status = ((best_block -> size_status & ~3) - size - 4) | 2;
        block_tag *split_block_f = (block_tag*)((char*)best_block + (best_block -> size_status & ~3) - 4);
        split_block_f -> size_status = (best_block -> size_status & ~3) - size - 4;
        best_block -> size_status = size + 4 + 1 + 2;
    }
    else//the best block cannot be spilt, then we modify the status of next block
    {
        best_block -> size_status = best_block -> size_status | 1;
        block_tag *next = (block_tag*)((char*)best_block + (best_block -> size_status & ~3));
        next -> size_status = next -> size_status | 2;
    }
    best_block = (block_tag*)((char*)best_block + 4);//make the pointer points to payload
    Mem_Dump();//print to check test
    return best_block;
}

/*
 * Function for freeing up a previously allocated block 
 * Argument - ptr: Address of the payload of the allocated block to be freed up 
 * Returns 0 on success 
 * Returns -1 on failure 
 * Here is what this function should accomplish 
 * - Return -1 if ptr is NULL
 * - Return -1 if ptr is not within the range of memory allocated by Mem_Init()
 * - Return -1 if ptr is not 4 byte aligned
 * - Mark the block as free 
 * - Coalesce if one or both of the immediate neighbours are free 
 */
int Mem_Free(void *ptr){
	/* Your code goes in here */
    if(ptr == NULL)//Return -1 if ptr is NULL
        return -1;
    if((block_tag*)ptr < first_block || (block_tag*)ptr > (first_block + total_mem_size))//Return -1 if ptr is not within the range of memory allocated by Mem_Init()
        return -1;
    if(((char*)ptr - (char*)first_block) % 4 != 0)//Return -1 if ptr is not 4 byte aligned
        return -1;
    block_tag *current_block =(block_tag*)((char*)ptr - 4);//get the header of the ptr block
    current_block -> size_status = current_block -> size_status & ~1;//set the block we want to free free
    int curr_size = (current_block -> size_status & ~3);//length of size of the current block plus its header
    block_tag* next_block = (block_tag*)((char*)current_block + curr_size);
    //the preivous is empty and the next is allocated
    if((current_block -> size_status & 2) == 0)
    {

        block_tag* pre_block_f = (block_tag*)((char*)current_block - 4);//set the previous block's footer
        block_tag* pre_block = (block_tag*)((char*)current_block - pre_block_f -> size_status);//set the previous block's header
      if((next_block -> size_status & 1) == 1)
      {
        pre_block -> size_status = ((pre_block -> size_status & ~3) + curr_size) | 2;//modify the previous block's status
        block_tag* current_block_f = (block_tag*)((char*)current_block + curr_size - 4);//set the current free block's footer
        current_block_f -> size_status = (pre_block -> size_status & ~3);//modify the current block footer's status
        // check if next exist
        next_block -> size_status = next_block -> size_status & ~2;//modify the next block header's status
      }
    //the previous is empty and the next is empty
      else
      {
        block_tag* next_block_f = (block_tag*)((char*)next_block + (next_block -> size_status & ~3) -4);//set the next block's footer
        next_block_f -> size_status = (pre_block -> size_status & ~3) + curr_size + (next_block -> size_status & ~3);//modify the next block footer's status
        pre_block -> size_status = ((pre_block -> size_status & ~3) + curr_size + (next_block -> size_status & ~3)) | 2;//modify the previous block's status
      }
    }
    //the previous is allocated and the the next is allocated
    else if((current_block -> size_status & 2) == 2)
    {
      if((next_block -> size_status & 1) == 1)
      { 
        block_tag* current_block_f = (block_tag*)((char*)current_block + curr_size - 4);//set the current free block's footer
        current_block_f -> size_status = curr_size;//modify the current block footer's status
        current_block -> size_status = curr_size | 2;
        next_block -> size_status = next_block -> size_status & ~2;//modify the next block header's status
      }
    //the previous is allocated and the next is empty
      else
      {
        block_tag* next_block_f = (block_tag*)((char*)next_block + (next_block -> size_status & ~3) -4);//set the current free block's footer
        current_block -> size_status = ((next_block -> size_status & ~3) + curr_size) | 2;//modify the current block's status
        next_block_f -> size_status = current_block -> size_status & ~2;//modify the next block footer's status
      }
    }
    Mem_Dump();//print to check the test
    return 0;
}

/*
 * Function used to initialize the memory allocator
 * Not intended to be called more than once by a program
 * Argument - sizeOfRegion: Specifies the size of the chunk which needs to be allocated
 * Returns 0 on success and -1 on failure 
 */
int Mem_Init(int sizeOfRegion){
  int pagesize;
  int padsize;
  int fd;
  int alloc_size;
  void* space_ptr;
  static int allocated_once = 0;
  
  if(0 != allocated_once){
    fprintf(stderr,"Error:mem.c: Mem_Init has allocated space during a previous call\n");
    return -1;
  }
  if(sizeOfRegion <= 0){
    fprintf(stderr,"Error:mem.c: Requested block size is not positive\n");
    return -1;
  }

  // Get the pagesize
  pagesize = getpagesize();

  // Calculate padsize as the padding required to round up sizeOfRegion to a multiple of pagesize
  padsize = sizeOfRegion % pagesize;
  padsize = (pagesize - padsize) % pagesize;

  alloc_size = sizeOfRegion + padsize;

  // Using mmap to allocate memory
  fd = open("/dev/zero", O_RDWR);
  if(-1 == fd){
    fprintf(stderr,"Error:mem.c: Cannot open /dev/zero\n");
    return -1;
  }
  space_ptr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (MAP_FAILED == space_ptr){
    fprintf(stderr,"Error:mem.c: mmap cannot allocate space\n");
    allocated_once = 0;
    return -1;
  }
  
  allocated_once = 1;
  
  // Intialising total available memory size
  total_mem_size = alloc_size;

  // To begin with there is only one big free block
  first_block = (block_tag*) space_ptr;
  
  // Setting up the header
  first_block->size_status = alloc_size;
  // Marking the previous block as busy
  first_block->size_status += 2;

  // Setting up the footer
  block_tag *footer = (block_tag*)((char*)first_block + alloc_size - 4);
  footer->size_status = alloc_size;
  
  return 0;
}

/* 
 * Function to be used for debugging 
 * Prints out a list of all the blocks along with the following information for each block 
 * No.      : serial number of the block 
 * Status   : free/busy 
 * Prev     : status of previous block free/busy
 * t_Begin  : address of the first byte in the block (this is where the header starts) 
 * t_End    : address of the last byte in the block 
 * t_Size   : size of the block (as stored in the block header)(including the header/footer)
 */ 
void Mem_Dump() {
  int counter;
  char status[5];
  char p_status[5];
  char *t_begin = NULL;
  char *t_end = NULL;
  int t_size;

  block_tag *current = first_block;
  counter = 1;

  int busy_size = 0;
  int free_size = 0;
  int is_busy = -1;

  fprintf(stdout,"************************************Block list***********************************\n");
  fprintf(stdout,"No.\tStatus\tPrev\tt_Begin\t\tt_End\t\tt_Size\n");
  fprintf(stdout,"---------------------------------------------------------------------------------\n");
  
  while(current < (block_tag*)((char*)first_block + total_mem_size)){

    t_begin = (char*)current;
    
    t_size = current->size_status;
    
    if(t_size & 1){
      // LSB = 1 => busy block
      strcpy(status,"Busy");
      is_busy = 1;
      t_size = t_size - 1;
    }
    else{
      strcpy(status,"Free");
      is_busy = 0;
    }

    if(t_size & 2){
      strcpy(p_status,"Busy");
      t_size = t_size - 2;
    }
    else strcpy(p_status,"Free");

    if (is_busy) busy_size += t_size;
    else free_size += t_size;

    t_end = t_begin + t_size - 1;
    
    fprintf(stdout,"%d\t%s\t%s\t0x%08lx\t0x%08lx\t%d\n",counter,status,p_status,
                    (unsigned long int)t_begin,(unsigned long int)t_end,t_size);
    
    current = (block_tag*)((char*)current + t_size);
    counter = counter + 1;
  }
  fprintf(stdout,"---------------------------------------------------------------------------------\n");
  fprintf(stdout,"*********************************************************************************\n");

  fprintf(stdout,"Total busy size = %d\n",busy_size);
  fprintf(stdout,"Total free size = %d\n",free_size);
  fprintf(stdout,"Total size = %d\n",busy_size+free_size);
  fprintf(stdout,"*********************************************************************************\n");
  fflush(stdout);
  return;
}

