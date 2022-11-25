#pragma once
#include <stdio.h>
#include "windows_struct.h"


LPVOID EPROCESS_address(LPVOID ntoskernlBase);
LPVOID ntoskernl_base(void);
int GetPhysicalMemoryLayout(MEMORY_REGION* regions);