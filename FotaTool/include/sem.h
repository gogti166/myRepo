#include "cdef.h"

uint16 Sem_u16Wait(uint8 *u8Sem);
void Sem_vPost(uint8 *u8Sem);
void Sem_vAlloc(uint8 *u8Sem, uint8 u8Count);