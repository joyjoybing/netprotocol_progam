#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void handler(int sig)

{

   printf("Deal SIGINT...\n");  //SIGINT信号处理函数

}

 

int main()
{
	sigset_t newmask;
	sigset_t oldmask;
	sigset_t pendmask;

	struct sigaction act;

	act.sa_handler = handler; //handler为信号处理函数首地址

	sigemptyset(&act.sa_mask);

	act.sa_flags = 0;

	sigaction(SIGINT, &act, 0); //信号捕捉函数，捕捉Ctrl+C

	sigemptyset(&newmask);//初始化信号量集
	sigaddset(&newmask, SIGINT);//将SIGINT添加到信号量集中

	sigprocmask(SIG_BLOCK, &newmask, &oldmask);//将newmask中的SIGINT阻塞掉，并保存当前信号屏蔽字到Oldmask

	sleep (8);//休眠5秒钟，说明:在5s休眠期间，任何SIGINT信号都会被阻塞，如果在5s内收到任何键盘的Ctrl+C信号，则此时会把这些信息存在内核的队列中，等待5s结束后，可能要处理此信号。 
	sigpending(&pendmask);//检查信号是悬而未决的,

	if (sigismember(&pendmask, SIGINT))//SIGINT是悬而未决的。所谓悬而未决，是指SIGINT被阻塞还没有被处理
	{
		printf("SIGINT pending\n");
	}
//	sigprocmask(SIG_SETMASK, &oldmask, NULL);//恢复被屏蔽的信号SIGINT
	sigprocmask(SIG_UNBLOCK,&newmask,NULL);

 

 //此处开始处理信号，调用信号处理函数
	printf("SIGINT unblocked/n");

	return (0);

}
