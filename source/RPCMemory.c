#include "KMSServer.h"

// Memory allocation function for RPC.
// The runtime uses these two functions for allocating/deallocating
// enough memory to pass the string to the server.
void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
    return malloc(len);
}
 
// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void __RPC_FAR *ptr)
{
    free(ptr);
}