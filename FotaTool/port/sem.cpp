#include "cdef.h"
#include "ace/Time_Value.h"
#include "ace/OS.h"
#include "sem.h"

uint16 Sem_u16Wait(uint8 *u8Sem)
{
    ACE_Time_Value AceWaitTime(0, 10000);//10ms
    uint16 u16Lapse = 0;
    do
    {
        ACE_OS::sleep(AceWaitTime);
        u16Lapse++;
        if (u16Lapse == 0xFFFFFFFF)
        {
            printf("timeout\n");
            //ACE_DEBUG((LM_INFO, ACE_TEXT("Pcb fail\n")));
        }
        else//for debuf
        {
            printf("%d\n", u16Lapse);
        }
    } while (*u8Sem == 0);
    *u8Sem--;
    /* Return the time that have waited for */
    return u16Lapse;
}

void Sem_vPost(uint8 *u8Sem)
{
    *u8Sem++;
}

void Sem_vAlloc(uint8 *u8Sem, uint8 u8Count)
{
    *u8Sem = u8Count;
}