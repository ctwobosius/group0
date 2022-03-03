/* Opens a file and then closes it. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle;

// do { 
//   msg("open \"sample.txt\""); 
//   msg("\n OPEN %d", handle=open("sample.txt"));
//   if (!((handle = open("sample.txt")) > 1)) 
//     fail("FAILED open \"sample.txt\""); 
  
// } while (0);

  CHECK((handle = open("sample.txt")) > 1, "open \"sample.txt\"");
  msg("close \"sample.txt\"");
  close(handle);
}
