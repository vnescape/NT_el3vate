#pragma once
#include <stdio.h>
#include "windows_struct.h"


LPVOID EPROCESS_address(LPVOID ntoskernlBase);
LPVOID GetNToskernlBase(void);
int GetPhysicalMemoryLayout(MEMORY_REGION* regions);