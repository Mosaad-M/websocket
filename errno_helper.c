/* errno_helper.c — expose errno to Mojo via FFI.
 *
 * Mojo 0.26 cannot call __errno_location() or load UnsafePointer[Int32]
 * from errno without crashing the compiler. This tiny wrapper is the
 * workaround: compile to liberrno_helper.so and call mojo_get_errno().
 */
#include <errno.h>

int mojo_get_errno(void) { return errno; }
