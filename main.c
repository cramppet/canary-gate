#include <stdio.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef struct _hook { HANDLE hThread; void* addr; } hook_t;

LONG Handler(PEXCEPTION_POINTERS args) {
  PCONTEXT ctx = args->ContextRecord; 
  PEXCEPTION_RECORD exc = args->ExceptionRecord;
  if (exc->ExceptionCode == EXCEPTION_SINGLE_STEP) {
    printf("Handler caught exception: %p, RAX = 0x%llx\n", ctx->Rip, ctx->Rax);
    ctx->Dr0 = 0;
    ctx->Dr6 = 0;
    ctx->Dr7 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

void set_hook(hook_t* args) {
  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_ALL;
  SuspendThread(args->hThread);
  GetThreadContext(args->hThread, &ctx);
  ctx.Dr0 = args->addr;
  ctx.Dr6 = 0;
  ctx.Dr7 = 1;
  SetThreadContext(args->hThread, &ctx);
  ResumeThread(args->hThread);
}

int main() {
  HMODULE ntdll = GetModuleHandleA("NTDLL.DLL");
  PBYTE func = GetProcAddress(ntdll, "NtQueryInformationProcess");
  DWORD i = 0;
  hook_t hook = {0};
  
  //
  // Locate desired NTDLL function, we assume it has a "syscall" instruction
  // preserved
  //

  while (1) {
    if (func[i] == 0x0F && func[i+1] == 0x05) {
      printf("Found syscall instruction at: %p\n", func + i);
      hook.addr = func + i;
      break;
    }
    printf("Byte value = 0x%x\n", func[i]);
    i += 1;
  }

  //
  // Get a non-pseudohandle for our current thread and add the exception handler
  // (hook) to capture the RAX value after the EDR hook has executed
  //

  hook.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
  AddVectoredExceptionHandler(1, Handler);

  //
  // Create another thread to create the hook in our thread context
  //

  CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)set_hook, &hook, 0, NULL);
  Sleep(10000);

  //
  // Make the "canary call" in order to reveal the syscall number
  //

  printf("Calling function...\n");

  PROCESS_BASIC_INFORMATION info = {0};
  ((NtQueryInformationProcess_t*)func)(-1, ProcessBasicInformation, &info, sizeof(PROCESS_BASIC_INFORMATION), NULL);

  printf("Exiting...\n");

  return 0;
}
