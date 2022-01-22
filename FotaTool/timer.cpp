#include "timer.h"

void Timer::Timer_vRegister(Timer_tenTID Timer_enTID, const uint16 u16Delay, const uint16 u16Interval)
{
    uint8 u8Index = 0;
    for (u8Index = 0; u8Index < TIMER_NUMBER; u8Index++)
    {
        if (astTimer[u8Index].boRegted == false)
        {
            astTimer[u8Index].boRegted = true;
            astTimer[u8Index].u8TimeId = Timer_enTID;
            astTimer[u8Index].iDelaySec = u16Delay / 1000;
            astTimer[u8Index].iDelayMlisec = u16Delay % 1000;
            astTimer[u8Index].iIntervalSec = u16Interval / 1000;
            astTimer[u8Index].iIntervalMliSec = u16Interval % 1000;
            break;
        }
    }
    if (u8Index >= TIMER_NUMBER)
    {
        printf("No Timer Space\n");
    }
}

void Timer::Timer_vRegister(Timer_tenTID Timer_enTID, const uint16 u16Interval)
{
    uint8 u8Index = 0;
    for (u8Index = 0; u8Index < TIMER_NUMBER; u8Index++)
    {
        if (astTimer[u8Index].boRegted == false)
        {
            astTimer[u8Index].boRegted = true;
            astTimer[u8Index].u8TimeId = Timer_enTID;
            astTimer[u8Index].iDelaySec = u16Interval / 1000;
            astTimer[u8Index].iDelayMlisec = u16Interval % 1000;
            astTimer[u8Index].iIntervalSec = u16Interval / 1000;
            astTimer[u8Index].iIntervalMliSec = u16Interval % 1000;
            break;
        }
    }
    if (u8Index >= TIMER_NUMBER)
    {
        printf("No Timer Space\n");
    }
}

void Timer::Timer_vDeRegister(Timer_tenTID Timer_enTID)
{
    uint8 u8Index = 0;
    for (u8Index = 0; u8Index < TIMER_NUMBER; u8Index++)
    {
        if (astTimer[u8Index].u8TimeId == Timer_enTID)
        {
            astTimer[u8Index].boRegted = false;
            break;
        }
    }
    if (u8Index >= TIMER_NUMBER)
    {
        printf("Nerver Register\n");
    }
}

void Timer::Timer_vStart(Timer_tenTID Timer_enTID)
{
    uint8 u8Index = 0;
    for (u8Index = 0; u8Index < TIMER_NUMBER; u8Index++)
    {
        if (astTimer[u8Index].u8TimeId == Timer_enTID)
        {
            astTimer[u8Index].lTimeHandle = ACE_Reactor::instance()->schedule_timer(this, &(astTimer[u8Index].u8TimeId),
                ACE_Time_Value(astTimer[u8Index].iDelaySec, astTimer[u8Index].iDelayMlisec * 1000),
                ACE_Time_Value(astTimer[u8Index].iIntervalSec, astTimer[u8Index].iIntervalMliSec * 1000));
            if (astTimer[u8Index].lTimeHandle < 0)
            {
                printf("Timer Start Failed:%d\n", Timer_enTID);
            }
            else
            {
                astTimer[u8Index].boStart = true;
                if (boBlock_ == True)
                {
                    semp_->acquire();
                }
            }
            break;
        }
    }
    if (u8Index >= TIMER_NUMBER)
    {
        printf("Not register\n");
    }
}

void Timer::Timer_vClear(Timer_tenTID Timer_enTID)
{
    uint8 u8Index = 0;
    /* Find the specific timerId and cancle it. */
    for (u8Index = 0; u8Index < TIMER_NUMBER; u8Index++)
    {
        if ((astTimer[u8Index].u8TimeId == Timer_enTID) && (astTimer[u8Index].boStart == True))
        {
            ACE_Reactor::instance()->cancel_timer(astTimer[u8Index].lTimeHandle);
            astTimer[u8Index].boStart = False;
            break;
        }
    }

    if (boBlock_ == True)
    {
        semp_->release();
    }
    /* Find nothing */
    if (u8Index >= TIMER_NUMBER)
    {
        //printf("Not start\n");
    }
}

void Timer::Timer_vStop()
{
    ACE_Reactor::instance()->end_reactor_event_loop();
}

int Timer::handle_timeout(const ACE_Time_Value&, const void *act)
{
    Timer_tenTID enTimerID = (Timer_tenTID)(*((uint8*)act));
    switch (enTimerID)
    {
    case Timer_nenCycle200ms:
        printf("ACK err\n");
        break;

    case AUTH_nenCycle2s:
        //printf("Auth\n");
        //vSendAuth();
        break;

    case FotaTest300ms:
        printf("300ms\n");

    default:
        printf("Unknow timer\n");
        break;
    }
    return 0;
}