#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/errno.h>

#include <asm/current.h>
#include <linux/sched.h>

#include <linux/uaccess.h>
#include <linux/poll.h>

#include <asm/atomic.h>
#include <linux/mutex.h>

#include <linux/wait.h>

#include <linux/device.h>
static struct class *cls = NULL;

static int major = 0;
static int minor = 0;
const  int count = 6;

#define DEVNAME "demo"

static struct cdev *demop = NULL;
static atomic_t tv;
static wait_queue_head_t wq;

static struct fasync_struct *fasync = NULL;//�����첽֪ͨ�ṹ��

#define KMAX 1024
static char kbuf[KMAX];
static int counter = 0;

//���豸
static int demo_open(struct inode *inode, struct file *filp)
{
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    if(!atomic_dec_and_test(&tv)){
        atomic_inc(&tv);
        return -EBUSY;
    }

    memset(kbuf, 0, KMAX);
    counter = 0;

    return 0;
}

//�ر��豸
static int demo_release(struct inode *inode, struct file *filp)
{
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    atomic_inc(&tv);
    return 0;
}

//���豸
//ssize_t read(int fd, void *buf, size_t count)
static ssize_t demo_read(struct file *filp, char __user *buf, size_t size, loff_t *offset)
{
    int err = 0;
    struct inode *inode = filp->f_path.dentry->d_inode;  //��ȡ�ļ���inod��
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    if(!counter){
        if(filp->f_flags & O_NONBLOCK){
            return -EAGAIN;
        }

        err = wait_event_interruptible(wq, (0 != counter));//˯�������ϵĵȴ�����
        if(err){                                            //û�����ɶ���˯
            return err;
        }
    }

    if(counter < size){
        size = counter;
    }

    if(copy_to_user(buf, kbuf, size)){
        return -EAGAIN;
    }

    counter = 0;

    return size;
}

//д�豸
static ssize_t demo_write(struct file *filp, const char __user *buf, size_t size, loff_t *offset)
{
    struct inode *inode = filp->f_path.dentry->d_inode;
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    if(size > KMAX){
        return -ENOMEM;
    }

    if(copy_from_user(kbuf, buf, size)){
        return -EAGAIN;
    }

    counter = size;
    wake_up_interruptible(&wq);//�㲥���ѵȴ�����
    kill_fasync(&fasync, SIGIO, POLLIN);//��fasync�ṹ�巢�ź�,
    //��fasync�����Ľ���(ͨ��fcntl(...,pid)ϵ�к�������)�ͻ��յ�SIGIO�ź�

    return size;
}

/* IO��·����֧��*/
static unsigned int demo_poll(struct file *filp, struct poll_table_struct *pts)
{
    unsigned int mask = 0;
    struct inode *inode = filp->f_path.dentry->d_inode;
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    poll_wait(filp, &wq, pts);//io��·����֧��,ֻ�еȴ��������о������¼��Ż������ߣ���������

    if(counter){
        mask = (POLLIN | POLLRDNORM);//���أ��������ò��poll�����������¼��������¼�
    }

    return mask;
}


/*�첽֪ͨ�ӿں�����Ӧ�ò��fcntl()ʱ�����˺���*/
static int demo_fasync(int fd, struct file *filp, int mode)
{
    struct inode *inode = filp->f_path.dentry->d_inode;
    //get major and minor from inode
    printk(KERN_INFO "(major=%d, minor=%d), %s : %s : %d\n",
        imajor(inode), iminor(inode), __FILE__, __func__, __LINE__);

    return fasync_helper(fd, filp, mode, &fasync);//����mod,���첽֪ͨ�ṹ���������
                                                //���ߴ��������Ƴ����õ���Ϣ����䵽fasync�ṹ����
}

static struct file_operations fops = {
    .owner  = THIS_MODULE,
    .open   = demo_open,
    .release= demo_release,
    .read   = demo_read,
    .write  = demo_write,
    .poll   = demo_poll,
    .fasync = demo_fasync,
};

static int __init demo_init(void)
{
    dev_t devnum;
    int ret, i;

    struct device *devp = NULL;

    //get command and pid
    printk(KERN_INFO "(%s:pid=%d), %s : %s : %d\n",
        current->comm, current->pid, __FILE__, __func__, __LINE__);

    //1. alloc cdev obj
    demop = cdev_alloc();
    if(NULL == demop){
        return -ENOMEM;
    }

    //2. init cdev obj
    cdev_init(demop, &fops);

    ret = alloc_chrdev_region(&devnum, minor, count, DEVNAME);
    if(ret){
        goto ERR_STEP;
    }
    major = MAJOR(devnum);

    //3. register cdev obj
    ret = cdev_add(demop, devnum, count);
    if(ret){
        goto ERR_STEP1;
    }

    cls = class_create(THIS_MODULE, DEVNAME);
    if(IS_ERR(cls)){
        ret = PTR_ERR(cls);
        goto ERR_STEP1;
    }

    for(i = minor; i < (count+minor); i++){
        devp = device_create(cls, NULL, MKDEV(major, i), NULL, "%s%d", DEVNAME, i);
        if(IS_ERR(devp)){
            ret = PTR_ERR(devp);
            goto ERR_STEP2;
        }
    }

    // init atomic_t
    atomic_set(&tv, 1);

    init_waitqueue_head(&wq);//��ʼ���ȴ�����

    //get command and pid
    printk(KERN_INFO "(%s:pid=%d), %s : %s : %d - ok.\n",
        current->comm, current->pid, __FILE__, __func__, __LINE__);
    return 0;

ERR_STEP2:
    for(--i; i >= minor; i--){
        device_destroy(cls, MKDEV(major, i));
    }
    class_destroy(cls);

ERR_STEP1:
    unregister_chrdev_region(devnum, count);

ERR_STEP:
    cdev_del(demop);

    //get command and pid
    printk(KERN_INFO "(%s:pid=%d), %s : %s : %d - fail.\n",
        current->comm, current->pid, __FILE__, __func__, __LINE__);
    return ret;
}

static void __exit demo_exit(void)
{
    int i;
    //get command and pid
    printk(KERN_INFO "(%s:pid=%d), %s : %s : %d - leave.\n",
        current->comm, current->pid, __FILE__, __func__, __LINE__);

    for(i=minor; i < (count+minor); i++){
        device_destroy(cls, MKDEV(major, i));
    }
    class_destroy(cls);

    unregister_chrdev_region(MKDEV(major, minor), count);
    cdev_del(demop);
}

module_init(demo_init);
module_exit(demo_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Farsight");
MODULE_DESCRIPTION("Demo for kernel module");