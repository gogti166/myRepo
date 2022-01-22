#ifndef __THREAD_H__
#define __THREAD_H__

#include <ace/Task.h>
#include <ace/Thread.h>

#include "interface.h"

class EventLoop_Tsk : public ACE_Task_Base
{
public:
    virtual int open(void *args = 0)
    {
        return activate();
    }
    
    virtual int close(void)
    {
        //ACE_DEBUG((LM_DEBUG, "EventLoop_Tsk down \n"));
        delete this;
        return 0;
    }

    virtual int svc(void);
private:
};

class Handle_Tsk : public ACE_Task<ACE_MT_SYNCH>
{
public:
    Handle_Tsk()
    {
        boMalloced = False;
    }

    virtual int open()
    {
        return activate();
    }

    virtual int close(void)
    {
        ACE_DEBUG((LM_DEBUG, "Handle_task down \n"));
        delete this;
        return 0;
    }

    virtual int svc(void);

private:
    bool boMalloced;
};

/* This task is used to receive all messages from cluster. */
class Recv_Tsk : public ACE_Task<ACE_MT_SYNCH>
{
public:
    Recv_Tsk(Handle_Tsk* Handle, pcap_t *pSockfd):HandleTask(Handle), pFd(pSockfd)
    {
        //boLoop = true;
    }

    virtual int open()
    {
        return activate();
    }

    virtual int close(void)
    {
        ACE_DEBUG((LM_DEBUG, "Recv_task down \n"));
        delete this;
        return 0;
    }

    virtual int svc(void);

private:    
    Handle_Tsk* HandleTask;
    pcap_t* pFd;
};

#endif