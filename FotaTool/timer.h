#ifndef __TIMER_H__
#define __TIMER_H__

#include "cdef.h"
#include <ace/Select_Reactor.h>

#define TIMER_NUMBER 10

typedef enum
{
    FotaTest300ms,
    Timer_nenCycle200ms,
    AUTH_nenCycle2s,
    Timer_nenMaxNum
}Timer_tenTID;

typedef struct
{
    uint8  u8TimeId; 
    bool   boRegted;
    int iDelaySec;
    int iDelayMlisec;
    int iIntervalSec;
    int iIntervalMliSec;

    long   lTimeHandle;
    bool   boStart;

    uint32 u32Delay;
    uint32 u32Interval;
}Timer_tstUser;

class Timer : public ACE_Event_Handler
{
public:
    Timer(bool boBlock) :boBlock_(boBlock)
    {
        if (boBlock == True)
        {
            semp_ = new ACE_Semaphore(0);
        }
        memset(astTimer, 0x00, sizeof(astTimer));
    }

    void Timer_vRegister(Timer_tenTID Timer_enTID, const uint16 u16Delay, const uint16 u16Interval);
    void Timer_vRegister(Timer_tenTID Timer_enTID, const uint16 u16Interval);
    void Timer_vDeRegister(Timer_tenTID Timer_enTID);
    void Timer_vStart(Timer_tenTID Timer_enTID);
    void Timer_vClear(Timer_tenTID Timer_enTID);
    void Timer_vStop();
    virtual int handle_timeout(const ACE_Time_Value&, const void *act);

private:
    uint32 u32AckSeq_;
    bool boBlock_;
    ACE_Semaphore* semp_;
    /* maximum timeID 10 */
    Timer_tstUser astTimer[TIMER_NUMBER];
};

#endif