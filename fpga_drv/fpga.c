#include <linux/init.h>
#include <linux/module.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include "../common/common.h"
//alloc_bootmem

#define debug 1

#if debug
#define DEBUG(format, ...)          printk("\033[40;34mDEBUG\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
#define DEBUG(format, ...)
#endif

#define WARNING(format, ...)        printk("\033[40;33mWARNING\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define ERROR(format, ...)          printk(KERN_ERR"\033[40;31mERROR\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);

#define FPGA_TASK_INPUT_REG(base)    (base + 0x200)     //0-31:addr(M) 32-63:size(byte)
#define FPGA_TASK_OUTPUT_REG(base)   (base + 0x300)     //0-31:addr(M) 32-63:size(byte)
#define FPGA_SW_INIT_REG(base)       (base + 0x500)

#define FPGA_SOFT_RESET(base)           (base + 0x000)
#define FPGA_TASK_NUM(base)             (base + 0x100)   //0-11:所有的任务数 12-23:core0 24-35：core1 36-47:core2 48-59:core3
#define FPGA_TIME(base)                 (base + 0x108)
#define FPGA_TASK_COUNTER(base)         (base + 0x110)
#define FPGA_TASK_EMTPY(base)           (base + 0x118)
#define FPGA_CORE0_TASK_COUNTER(base)         (base + 0x120)
#define FPGA_CORE0_TASK_EMTPY(base)           (base + 0x128)
#define FPGA_CORE1_TASK_COUNTER(base)         (base + 0x130)
#define FPGA_CORE1_TASK_EMTPY(base)           (base + 0x138)
#define FPGA_CORE2_TASK_COUNTER(base)         (base + 0x140)
#define FPGA_CORE2_TASK_EMTPY(base)           (base + 0x148)
#define FPGA_CORE3_TASK_COUNTER(base)         (base + 0x150)
#define FPGA_CORE3_TASK_EMTPY(base)           (base + 0x158)

#define FPGA_SIZE_OFFSET    (32)
#define FPGA_ADDR_OFFSET    (20)

#define HIGH_MASK   (0xffffffff00000000)
#define LOW_MASK    (0x00000000ffffffff)

#define TOTAL_TASK_MASK     0x00000000ffffffff
#define TOTAL_PH_TASK_MASK  0x0000ffff00000000
#define TOTAL_SW_TASK_MASK  0xffff000000000000

#define MAX_DEV_NUM     (255)


#define PCI_DEVICE_ID_XILINX_PCIE_LYY 0x9041
#define PCI_DEVICE_ID_XILINX_PCIE_GSB 0x9040

#define MEM_ALIGNMENT           4
#define MEM_ALIGN_SIZE(size) (((size) + MEM_ALIGNMENT - 1) & ~(MEM_ALIGNMENT-1))

struct fpga_result {
    dma_addr_t dma_phy;
    unsigned int size;
    
    struct list_head list;
};

struct fpga_task {
    //addr and size
    unsigned long long reg_data;
    
    dma_addr_t dma_phy;
    unsigned int size;
    unsigned int type;
    
    struct list_head list;
};

//fpga device
struct fpga_dev {
    __u32 device_id;
    char name[16];
    char file_path[32];
    
    //device info
    dev_t dev;
    struct pci_dev* pci_dev;
    
    //task
    spinlock_t task_lock;
    int task_num;                   //FPGA中的任务数量
    
    spinlock_t task_list_lock;
    struct list_head task_list;     //待提交的任务队列
    struct work_struct submit_task; //工作队列提交任务
    atomic_t to_submit_num;         //待提交的任务数
    
    //result
    spinlock_t sw_result_lock;
    struct list_head sw_result_list;
    int sw_result_num;
    
    spinlock_t cd_result_lock;
    struct list_head cd_result_list;
    int cd_result_num;
    
    spinlock_t cs_result_lock;
    struct list_head cs_result_list;
    int cs_result_num;
    
    
    //reg bar info
    phys_addr_t reg_handle;
    size_t reg_size;
    void* regs;
    
    //wait queue
    wait_queue_head_t read_sw_wait;
    wait_queue_head_t read_cd_wait;
    wait_queue_head_t read_cs_wait;
    
    struct device *drv_device;
    
    unsigned int repeat_result;
    unsigned int error_result;
    
    int exit_flag;
    
    //operations
    int (*write_task)(void __iomem* reg, dma_addr_t addr, unsigned int size, unsigned int type);
    int (*read_result)(void __iomem* reg, dma_addr_t *addr, unsigned int *size, unsigned int* type);
    
    //fpga task statistics
    u64 time_reg;
    u64 task_num_reg;
    u64 task_counter_reg;
    u64 task_emtpy_reg;
    
    u64 task_core_counter_reg[4];
    u64 task_core_emtpy_reg[4];
    
    u64 total_num;
    u64 core_num[4];
};

struct module_info {
    struct fpga_dev* fpga_dev_a[MAX_DEV_NUM];
    struct cdev cdev;
}module_info;


extern unsigned int mem_phy_offset(dma_addr_t phy_addr);
extern void* mem_vir_addr(unsigned int offset);
extern dma_addr_t mem_phy_addr(unsigned int offset);

static unsigned int major = 0;
static unsigned int minor = 0;
static const unsigned int minor_base = 0;
static struct class *class;
static struct proc_dir_entry *proc_entry;

static unsigned int sw_submit_num = 0;
static unsigned int sw_recv_num = 0;

static unsigned int cd_submit_num = 0;
static unsigned int cd_recv_num = 0;

static unsigned int cs_submit_num = 0;
static unsigned int cs_recv_num = 0;

static int task_num = 0;
static int max_task_num = 0;

static const struct pci_device_id fpga_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_XILINX,	PCI_DEVICE_ID_XILINX_PCIE_LYY), },
    { PCI_DEVICE(PCI_VENDOR_ID_XILINX,	PCI_DEVICE_ID_XILINX_PCIE_GSB), },
	{ },
};

int write_sw_task(void __iomem *reg, dma_addr_t addr, unsigned int size, unsigned int type)
{
    unsigned long long reg_data = 0;
    
    reg_data = size - 4096;
    reg_data = (reg_data << FPGA_SIZE_OFFSET);
    reg_data = reg_data | ((u64)addr >> FPGA_ADDR_OFFSET);
    sw_submit_num++;
    DEBUG("[%d]reg_data=0x%llx", sw_submit_num, reg_data);
    writeq(reg_data, reg);
    
    return 0;
}

int read_sw_result(void __iomem *reg, dma_addr_t *addr, unsigned int *size, unsigned int* type)
{
    unsigned long long reg_data = 0;
    
    reg_data = readq(reg);
    *size = (reg_data & HIGH_MASK) >> FPGA_SIZE_OFFSET;
    *size += 4096;
    *addr = (reg_data & LOW_MASK) << FPGA_ADDR_OFFSET;
    *type = K_RET_TYPE_SW;
    if(*size == 4096) {
        return 0;
    }
    sw_recv_num++;
    return 1;
}

int write_chindp_task(void __iomem *reg, dma_addr_t addr, unsigned int size, unsigned int type)
{
    unsigned long long reg_data = 0;
    
    DEBUG("addr=%llx, type=%d, size=%d", addr, type, size);
    reg_data = size;
    reg_data = (reg_data << 32);
    reg_data = reg_data | ((u64)type << 28);
    reg_data = reg_data | ((u64)addr >> 20);
    if(type == K_RET_TYPE_CD) {
        cd_submit_num++;
    }
    else if(type == K_RET_TYPE_CS) {
        cs_submit_num++;
    }
    DEBUG("reg_data=0x%llx", reg_data);
    writeq(reg_data, reg);
    return 0;
}

int read_chindp_result(void __iomem *reg, dma_addr_t *addr, unsigned int *size, unsigned int* type)
{
    unsigned long long reg_data = 0;
    
    reg_data = readq(reg);
    
    DEBUG("reg_data=0x%llx", reg_data);
    
    *size = (reg_data & 0xffffffff00000000) >> 32;
    *addr = (reg_data & 0x000000000fffffff) << 20;
    *type = (reg_data & 0x00000000f0000000) >> 28;
    if(*type == K_RET_TYPE_CD) {
        cd_recv_num++;
    }
    else if(*type == K_RET_TYPE_CS) {
        cs_recv_num++;
    }
    return *size;
}

void init_fpga_task_statistics(struct fpga_dev* fpga_dev)
{
    fpga_dev->time_reg = 0;
    fpga_dev->task_num_reg = 0;
    fpga_dev->task_counter_reg = 0;
    fpga_dev->task_emtpy_reg = 0;
    fpga_dev->task_core_counter_reg[0] = 0;
    fpga_dev->task_core_emtpy_reg[0] = 0;
    fpga_dev->task_core_counter_reg[1] = 0;
    fpga_dev->task_core_emtpy_reg[1] = 0;
    fpga_dev->task_core_counter_reg[2] = 0;
    fpga_dev->task_core_emtpy_reg[2] = 0;
    fpga_dev->task_core_counter_reg[3] = 0;
    fpga_dev->task_core_emtpy_reg[3] = 0;
    fpga_dev->total_num = 0;
    fpga_dev->core_num[0] = 0;
    fpga_dev->core_num[1] = 0;
    fpga_dev->core_num[2] = 0;
    fpga_dev->core_num[3] = 0;
}

static void submit_task(struct work_struct *work)
{
    struct fpga_task* task = NULL;
    struct fpga_dev *fpga_dev = container_of(work, struct fpga_dev, submit_task);
    struct list_head* first_node = NULL;
    unsigned long flags;
    DEBUG("Entry submit_task");

    spin_lock_irqsave(&fpga_dev->task_lock, flags);
    spin_lock(&fpga_dev->task_list_lock);
    while(fpga_dev->task_num < MAX_TASK_NUM && !list_empty(&fpga_dev->task_list)) {
        fpga_dev->task_num++;
            
        first_node = fpga_dev->task_list.next;
        task = list_entry(first_node, struct fpga_task, list);
        if(task) {
            fpga_dev->write_task(FPGA_TASK_INPUT_REG(fpga_dev->regs), task->dma_phy, task->size, task->type);
            list_del_init(&task->list);
            kfree(task);
            atomic_sub(1, &fpga_dev->to_submit_num);
            task_num--;
        }
    }
    spin_unlock(&fpga_dev->task_list_lock);
    spin_unlock_irqrestore(&fpga_dev->task_lock, flags);
    
    return;
}

int fpga_open(struct inode *inode, struct file *filp)
{
    struct fpga_dev* fpga_dev;
    struct pci_dev *pdev;
    unsigned long flags;
    DEBUG("Entry fpga_open");
    fpga_dev = module_info.fpga_dev_a[MINOR(inode->i_rdev)];
    if(fpga_dev == NULL) {
        ERROR("fpga_dev is NULL, minor=%d", MINOR(inode->i_rdev));
        return -ENOENT;
    }
    filp->private_data = (void *)fpga_dev;
    pdev = fpga_dev->pci_dev;

    DEBUG("fpga_open, minor=%d", MINOR(inode->i_rdev));
    
    //reset fpge counter
    writeq(0x1, FPGA_SOFT_RESET(fpga_dev->regs));
    init_fpga_task_statistics(fpga_dev);
    
    spin_lock_irqsave(&fpga_dev->sw_result_lock, flags);
    INIT_LIST_HEAD(&fpga_dev->sw_result_list);
    fpga_dev->sw_result_num = 0;
    spin_unlock_irqrestore(&fpga_dev->sw_result_lock, flags);
    
    spin_lock_irqsave(&fpga_dev->cd_result_lock, flags);
    INIT_LIST_HEAD(&fpga_dev->cd_result_list);
    fpga_dev->cd_result_num = 0;
    spin_unlock_irqrestore(&fpga_dev->cd_result_lock, flags);
    
    spin_lock_irqsave(&fpga_dev->cs_result_lock, flags);
    INIT_LIST_HEAD(&fpga_dev->cs_result_list);
    fpga_dev->cs_result_num = 0;
    spin_unlock_irqrestore(&fpga_dev->cs_result_lock, flags);
    
    spin_lock(&fpga_dev->task_list_lock);
    INIT_LIST_HEAD(&fpga_dev->task_list);
    spin_unlock(&fpga_dev->task_list_lock);
    
    spin_lock_irqsave(&fpga_dev->task_lock, flags);
    fpga_dev->task_num = 0;
    spin_unlock_irqrestore(&fpga_dev->task_lock, flags);
    
    INIT_WORK(&fpga_dev->submit_task, submit_task);
    
    DEBUG("Exit fpga_open");
    return 0;
    
}

int fpga_release(struct inode *inode, struct file *filp)
{   
    //int i = 0;
    struct fpga_dev* fpga_dev = (struct fpga_dev*)filp->private_data;
    //struct pci_dev *pdev = fpga_dev->pci_dev;
    DEBUG("Entry fpga_release");

    DEBUG("Exit fpga_release");
    return 0;
}

inline void wait_result(wait_queue_head_t *wq, int condition)
{
    DEFINE_WAIT(__wait);
    
    if (!(condition)) {
        for (;;) {
            prepare_to_wait(wq, &__wait, TASK_INTERRUPTIBLE);
            if (condition)
                break;
            DEBUG("schedule before");
            schedule();
            DEBUG("schedule after");
            break;
        }
        finish_wait(wq, &__wait);
    }
    
    return;
}
    
long fpag_ioctl(struct file *filp, unsigned int request, unsigned long arg)
{
    int ret = 0;
    int err = 0;
    struct fpga_dev* fpga_dev = (struct fpga_dev*)filp->private_data;
    struct test_data data;
    struct data_info data_info;
    void* dma_vir;
    dma_addr_t dma_phy;
    struct fpga_result* result = NULL;
    struct fpga_task* node = NULL;
    unsigned long flags;
    DEFINE_WAIT(__wait);
    
    switch(request) {
        case FPGA_APPLY_RESULT_BUF:
            DEBUG("FPGA_APPLY_RESULT_BUF");
            if(copy_from_user((void *)&data_info, (void __user*)arg, sizeof(struct data_info))) {
                ERROR("copy_from_user failed");
                ret = -EFAULT;
                break;
            }
            
            if(data_info.type == K_RET_TYPE_SW) {
                DEBUG("get sw result");
                spin_lock_irqsave(&fpga_dev->sw_result_lock, flags);
                while(list_empty(&fpga_dev->sw_result_list)) {
                    spin_unlock_irqrestore(&fpga_dev->sw_result_lock, flags);

                    if(filp->f_flags & O_NONBLOCK) {
                        return -EAGAIN;
                    }
                    
                    if(fpga_dev->exit_flag == 1) {   //do not need wait result, exit block
                        fpga_dev->exit_flag = 0;
                        data_info.offset = 0;
                        data_info.data_size = 0;
                        if(copy_to_user((void __user*)arg, (void *)&data_info, sizeof(struct data_info))) {
                            ERROR("copy_to_user failed");
                            return -EFAULT;
                        }
                        return 0;
                    }
                    
                    //wait new data buf
                    //wait_event(fpga_dev->read_sw_wait, fpga_dev->sw_result_num);
                    wait_result(&fpga_dev->read_sw_wait, fpga_dev->sw_result_num);
                    
                    if(signal_pending(current)) {
                        if (sigismember(&current->pending.signal, SIGKILL) || sigismember(&current->pending.signal, SIGINT)) {
                            DEBUG("hanle sig KILL");
                            ret = -EAGAIN;
                            return ret;
                        }
                    }
                    
                    spin_lock_irqsave(&fpga_dev->sw_result_lock, flags);
                }
                
                if(!list_empty(&fpga_dev->sw_result_list)) {
                    struct list_head* first_node = fpga_dev->sw_result_list.next;
                    result = list_entry(first_node, struct fpga_result, list);
                    if(result) {
                        data_info.offset = mem_phy_offset(result->dma_phy);
                        data_info.data_size = result->size;
                        list_del_init(&result->list);
                        kfree(result);
                        fpga_dev->sw_result_num--;
                        spin_unlock_irqrestore(&fpga_dev->sw_result_lock, flags);
                        if(copy_to_user((void __user*)arg, (void *)&data_info, sizeof(struct data_info))) {
                            ERROR("copy_to_user failed");
                            return -EFAULT;
                        }
                        
                        return 0;
                    }
                }
                spin_unlock_irqrestore(&fpga_dev->sw_result_lock, flags);
            }
            else if(data_info.type == K_RET_TYPE_CD) {
                DEBUG("get cd result");
                spin_lock_irqsave(&fpga_dev->cd_result_lock, flags);
                while(list_empty(&fpga_dev->cd_result_list)) {
                    spin_unlock_irqrestore(&fpga_dev->cd_result_lock, flags);

                    if(filp->f_flags & O_NONBLOCK) {
                        return -EAGAIN;
                    }
                    
                    if(fpga_dev->exit_flag == 1) {   //do not need wait result, exit block
                        fpga_dev->exit_flag = 0;
                        data_info.offset = 0;
                        data_info.data_size = 0;
                        if(copy_to_user((void __user*)arg, (void *)&data_info, sizeof(struct data_info))) {
                            ERROR("copy_to_user failed");
                            return -EFAULT;
                        }
                        return 0;
                    }
                    
                    //wait new data buf
                    //wait_event(fpga_dev->read_cd_wait, fpga_dev->cd_result_num);
                    wait_result(&fpga_dev->read_cd_wait, fpga_dev->cd_result_num);
                    
                    if(signal_pending(current)) {
                        if (sigismember(&current->pending.signal, SIGKILL) || sigismember(&current->pending.signal, SIGINT)) {
                            DEBUG("hanle sig KILL");
                            ret = -EAGAIN;
                            return ret;
                        }
                    }
                    
                    spin_lock_irqsave(&fpga_dev->cd_result_lock, flags);
                }
                
                if(!list_empty(&fpga_dev->cd_result_list)) {
                    struct list_head* first_node = fpga_dev->cd_result_list.next;
                    result = list_entry(first_node, struct fpga_result, list);
                    if(result) {
                        data_info.offset = mem_phy_offset(result->dma_phy);
                        data_info.data_size = result->size;
                        list_del_init(&result->list);
                        kfree(result);
                        fpga_dev->cd_result_num--;
                        spin_unlock_irqrestore(&fpga_dev->cd_result_lock, flags);
                        if(copy_to_user((void __user*)arg, (void *)&data_info, sizeof(struct data_info))) {
                            ERROR("copy_to_user failed");
                            return -EFAULT;
                        }
                        
                        return 0;
                    }
                }
                spin_unlock_irqrestore(&fpga_dev->cd_result_lock, flags);
            }
            else if(data_info.type == K_RET_TYPE_CS) {
                DEBUG("get cs result");
                spin_lock_irqsave(&fpga_dev->cs_result_lock, flags);
                while(list_empty(&fpga_dev->cs_result_list)) {
                    spin_unlock_irqrestore(&fpga_dev->cs_result_lock, flags);

                    if(filp->f_flags & O_NONBLOCK) {
                        return -EAGAIN;
                    }
                    
                    //wait new data buf
                    //wait_event(fpga_dev->read_cs_wait, fpga_dev->cs_result_num);
                    wait_result(&fpga_dev->read_cs_wait, fpga_dev->cs_result_num);
                    
                    if(signal_pending(current)) {
                        if (sigismember(&current->pending.signal, SIGKILL) || sigismember(&current->pending.signal, SIGINT)) {
                            DEBUG("hanle sig KILL");
                            ret = -EAGAIN;
                            return ret;
                        }
                    }
                    
                    spin_lock_irqsave(&fpga_dev->cs_result_lock, flags);
                }
                
                if(!list_empty(&fpga_dev->cs_result_list)) {
                    struct list_head* first_node = fpga_dev->cs_result_list.next;
                    result = list_entry(first_node, struct fpga_result, list);
                    if(result) {
                        data_info.offset = mem_phy_offset(result->dma_phy);
                        data_info.data_size = result->size;
                        list_del_init(&result->list);
                        kfree(result);
                        fpga_dev->cs_result_num--;
                        spin_unlock_irqrestore(&fpga_dev->cs_result_lock, flags);
                        if(copy_to_user((void __user*)arg, (void *)&data_info, sizeof(struct data_info))) {
                            ERROR("copy_to_user failed");
                            return -EFAULT;
                        }
                        
                        return 0;
                    }
                }
                spin_unlock_irqrestore(&fpga_dev->cs_result_lock, flags);
            }
            else {
                return -EINVAL;
            }
            ret = -EIO;
            ERROR("have no data buff");
            break;
        case FPGA_WRITE_BUF_SUBMIT:
            DEBUG("FPGA_WRITE_BUF_SUBMIT");
            
            if(copy_from_user((void *)&data_info, (void __user*)arg, sizeof(struct data_info))) {
                ERROR("copy_from_user failed");
                ret = -EFAULT;
                break;
            }
            
            dma_vir = mem_vir_addr(data_info.offset);
            if(dma_vir == NULL) {
                ERROR("dma virtual address is NULL");
                ret = -EINVAL;
                break;
            }
            dma_phy = pci_map_single(fpga_dev->pci_dev, dma_vir, data_info.data_size, PCI_DMA_TODEVICE);
            if ( 0 == dma_phy )  {
                ERROR("pci_map_single failed");
                ret = -EIO;
                break;
            }
            DEBUG("dma_phy=0x%llx, 0x%llx, type=%d, size=%d", dma_phy, mem_phy_addr(data_info.offset), data_info.type, data_info.data_size);
            
            spin_lock_irqsave(&fpga_dev->task_lock, flags);
            if(fpga_dev->task_num < MAX_TASK_NUM) {//提交任务
                fpga_dev->task_num++;
                spin_unlock_irqrestore(&fpga_dev->task_lock, flags);

                fpga_dev->write_task(FPGA_TASK_INPUT_REG(fpga_dev->regs), dma_phy, data_info.data_size, data_info.type);
            }
            else {//将任务挂载在待提交队列中
                spin_unlock_irqrestore(&fpga_dev->task_lock, flags);
                node = kmalloc(sizeof(struct fpga_task), GFP_KERNEL);
                if(!node) {
                    ERROR("kmalloc for fpga_task failed");
                    ret = -ENOMEM;
                    break;
                }
                node->dma_phy = dma_phy;
                node->size = data_info.data_size;
                node->type = data_info.type;
                
                spin_lock(&fpga_dev->task_list_lock);
                task_num++;
                if(task_num > max_task_num)
                    max_task_num = task_num;
                list_add_tail(&(node->list), &fpga_dev->task_list);
                spin_unlock(&fpga_dev->task_list_lock);
                
                atomic_add(1, &fpga_dev->to_submit_num);
            }
            
            break;
        case FPGA_EXIT_BLOCK:
            DEBUG("FPGA_EXIT_BLOCK");
            fpga_dev->exit_flag = 1;
            wake_up(&fpga_dev->read_sw_wait);
            wake_up(&fpga_dev->read_cd_wait);
            wake_up(&fpga_dev->read_cs_wait);
            break;
        case FPGA_IRQ:
            DEBUG("FPGA_IRQ");
            
            
            break;
        case FPGA_TEST_WRITE:
            DEBUG("FPGA_TEST_WRITE");
            if(copy_from_user((void *)&data, (void __user*)arg, sizeof(struct test_data))) {
                ERROR("copy_from_user failed");
                return -EFAULT;
            }
            DEBUG("write offset:%x data:0x%llx", data.offset, data.data);
            writeq(data.data, fpga_dev->regs + data.offset);
            
            break;
        case FPGA_TEST_READ:
            DEBUG("FPGA_TEST_READ");
            
            if(copy_from_user((void *)&data, (void __user*)arg, sizeof(struct test_data))) {
                ERROR("copy_from_user failed");
                return -EFAULT;
            }
            data.data = readq(fpga_dev->regs + data.offset);
            DEBUG("read offset:%x data:0x%llx", data.offset, data.data);
            if(copy_to_user((void *)arg, (void __user*)&data, sizeof(struct test_data))) {
                ERROR("copy_to_user failed");
                return -EFAULT;
            }

            break;
        default:
            ERROR("error request %d", request);
            break;
    }

    return ret;
}

ssize_t fpga_read(struct file *filp, char __user *buf, size_t n, loff_t *offset)
{
    return 0;
}

ssize_t fpga_write(struct file *filp, const char __user *buf, size_t n, loff_t *offset)
{
    return 0;
}
    
struct file_operations fpga_dev_ops = {
    .owner              = THIS_MODULE,
    .open               = fpga_open,
    .read               = fpga_read,
    .write              = fpga_write,
    .release            = fpga_release,
    .unlocked_ioctl     = fpag_ioctl,
};

irqreturn_t fpga_irq(int irq, void *data)
{
    struct fpga_dev* fpga_dev = data;
    int loop_flag;
    dma_addr_t dma_phy;
    int data_size;
    int count = 1;
    int type = 0;
    struct fpga_result* result = NULL;
    
    //DEBUG("Entry fpga_irq");
    //return IRQ_HANDLED;
    
    loop_flag = fpga_dev->read_result(FPGA_TASK_OUTPUT_REG(fpga_dev->regs), &dma_phy, &data_size, &type);
    if(loop_flag == 0) {
        return IRQ_HANDLED;
    }

    DEBUG("[%d]handle irq [0x%016llx][%d][%d]", count++, dma_phy, data_size, type);

    while(loop_flag) {
        if(data_size == -1) {
            fpga_dev->error_result++;
        }
        
        pci_unmap_single(fpga_dev->pci_dev, dma_phy, data_size, PCI_DMA_FROMDEVICE);
        
        result = kmalloc(sizeof(struct fpga_result), GFP_ATOMIC);
        if(!result) {
            ERROR("kmalloc fpga_result failed");
            return IRQ_HANDLED;
        }
        result->dma_phy = dma_phy;
        result->size = data_size;
#if 0
        if(fpga_dev->device_id == PCI_DEVICE_ID_XILINX_PCIE_LYY) {
            DEBUG("add ret to sw result list");
            spin_lock(&fpga_dev->sw_result_lock);
            list_add_tail(&(result->list), &fpga_dev->sw_result_list);
            fpga_dev->sw_result_num++;
            spin_unlock(&fpga_dev->sw_result_lock);
        }
        else if(fpga_dev->device_id == PCI_DEVICE_ID_XILINX_PCIE_GSB) {
            if(type == K_RET_TYPE_CD) {
                spin_lock(&fpga_dev->cd_result_lock);
                list_add_tail(&(result->list), &fpga_dev->cd_result_list);
                fpga_dev->cd_result_num++;
                spin_unlock(&fpga_dev->cd_result_lock);
            }
            else if(type == K_RET_TYPE_CS) {
                spin_lock(&fpga_dev->cs_result_lock);
                list_add_tail(&(result->list), &fpga_dev->cs_result_list);
                fpga_dev->cs_result_num++;
                spin_unlock(&fpga_dev->cs_result_lock);
            }
            else {
                ERROR("Unknown type:%d", type);
            }
        }
        else {
            ERROR("Unknown device id:%x", fpga_dev->device_id);
        }
#else
        if(type == K_RET_TYPE_SW) {
            DEBUG("add ret to sw result list");
            spin_lock(&fpga_dev->sw_result_lock);
            list_add_tail(&(result->list), &fpga_dev->sw_result_list);
            fpga_dev->sw_result_num++;
            spin_unlock(&fpga_dev->sw_result_lock);
        }
        else if(type == K_RET_TYPE_CD) {
            spin_lock(&fpga_dev->cd_result_lock);
            list_add_tail(&(result->list), &fpga_dev->cd_result_list);
            fpga_dev->cd_result_num++;
            spin_unlock(&fpga_dev->cd_result_lock);
        }
        else if(type == K_RET_TYPE_CS) {
            spin_lock(&fpga_dev->cs_result_lock);
            list_add_tail(&(result->list), &fpga_dev->cs_result_list);
            fpga_dev->cs_result_num++;
            spin_unlock(&fpga_dev->cs_result_lock);
        }
        else {
            ERROR("Unknown type:%d", type);
        }
#endif
        spin_lock(&fpga_dev->task_lock);
        fpga_dev->task_num--;
        spin_unlock(&fpga_dev->task_lock);
        
        loop_flag = fpga_dev->read_result(FPGA_TASK_OUTPUT_REG(fpga_dev->regs), &dma_phy, &data_size, &type);
        
        DEBUG("[%d]handle irq [0x%016llx][%d][%d]", count++, dma_phy ,data_size, type);
    }
    
    if(fpga_dev->sw_result_num) {
        DEBUG("wake up sw wait thread");
        wake_up(&fpga_dev->read_sw_wait);
    }
    if(fpga_dev->cd_result_num) {
        DEBUG("wake up cd wait thread");
        wake_up(&fpga_dev->read_cd_wait);
    }
    if(fpga_dev->cs_result_num) {
        DEBUG("wake up cs wait thread");
        wake_up(&fpga_dev->read_cs_wait);
    }
    
    if(atomic_read(&fpga_dev->to_submit_num) > 0) {
        schedule_work(&fpga_dev->submit_task);
    }
    return IRQ_HANDLED;
}

static int fpga_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    int ret = 0;
    struct fpga_dev* fpga_dev;
    struct pci_dev *rp;
    u16 old_cmd;
    unsigned char int_pin;
    u32 devcap;
    u16 ectl;
    
    DEBUG("Entry fpga_driver_probe");
    DEBUG("minor=%d", minor);

    if(minor >= MAX_DEV_NUM) {
        ERROR("minor(%d) is equal or large than MAX_DEV_NUM(%d)", minor, MAX_DEV_NUM);
        return -EPERM;
    }
    
    if(module_info.fpga_dev_a[minor] == NULL) {
        fpga_dev = kmalloc(sizeof(struct fpga_dev), GFP_KERNEL);
        if(fpga_dev == NULL) {
            ERROR("kmalloc fpga_dev failed");
            return -ENOMEM;
        }
        memset(fpga_dev, 0, sizeof(struct fpga_dev));
        module_info.fpga_dev_a[minor] = fpga_dev;
    }
    else {
        ERROR("kmalloc fpga_dev failed");
        return -EIO;
    }
    
    fpga_dev->device_id = ent->device;

    if(ent->device == PCI_DEVICE_ID_XILINX_PCIE_LYY) {
        DEBUG("lyy:device num:%x", PCI_DEVICE_ID_XILINX_PCIE_LYY);
        snprintf(fpga_dev->name, sizeof(fpga_dev->name), "fpga_lyy", minor);
        fpga_dev->write_task = write_sw_task;
        fpga_dev->read_result = read_sw_result;
    }
    else if(ent->device == PCI_DEVICE_ID_XILINX_PCIE_GSB) {
        DEBUG("gsb:device num:%x", PCI_DEVICE_ID_XILINX_PCIE_GSB);
        snprintf(fpga_dev->name, sizeof(fpga_dev->name), "fpga_gsb", minor);
        fpga_dev->write_task = write_chindp_task;
        fpga_dev->read_result = read_chindp_result;
    }
    else {
        ERROR("Device 0x%04x not support", ent->device);
        kfree(fpga_dev);
        return -ENODEV;
    }

    //create device file
    //fpga_dev->drv_device = device_create(class, NULL, MKDEV(major, minor), NULL, "fpga_%s", minor);
    fpga_dev->drv_device = device_create(class, NULL, MKDEV(major, minor), NULL, fpga_dev->name);
    if (IS_ERR(fpga_dev->drv_device)) {
		ERROR("failed to create device\n");
		ret = PTR_ERR(fpga_dev->drv_device);
        goto out0;
	}
    
    fpga_dev->dev = MKDEV(major, minor);
    DEBUG("fpga dev num:%d", fpga_dev->dev);
    DEBUG("fpga dev:%p", fpga_dev);
    
    snprintf(fpga_dev->file_path, sizeof(fpga_dev->file_path), "/dev/%s", fpga_dev->name);
    minor++;
    fpga_dev->pci_dev = pdev;
    
    init_waitqueue_head(&fpga_dev->read_sw_wait);
    init_waitqueue_head(&fpga_dev->read_cd_wait);
    init_waitqueue_head(&fpga_dev->read_cs_wait);
    
    spin_lock_init(&fpga_dev->sw_result_lock);
    INIT_LIST_HEAD(&fpga_dev->sw_result_list);
    
    spin_lock_init(&fpga_dev->cd_result_lock);
    INIT_LIST_HEAD(&fpga_dev->cd_result_list);
    
    spin_lock_init(&fpga_dev->cs_result_lock);
    INIT_LIST_HEAD(&fpga_dev->cs_result_list);
    
    //task list and task queue  info
    spin_lock_init(&fpga_dev->task_lock);
    fpga_dev->task_num = 0;
    
    
    spin_lock_init(&fpga_dev->task_list_lock);
    INIT_LIST_HEAD(&fpga_dev->task_list);
    
    atomic_set(&fpga_dev->to_submit_num, 0);
    
    
    pci_set_drvdata(pdev, (void *)fpga_dev);
    
    ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (!ret) {
		ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
        if (ret) {
            ERROR("pci_set_consistent_dma_mask failed\n");
        }
    }
    else {
        ERROR("pci_set_dma_mask failed");
    }
    
    fpga_dev->sw_result_num = 0;
    
    fpga_dev->reg_handle = pci_resource_start(pdev, 0);
    fpga_dev->reg_size = pci_resource_end(pdev, 0) - pci_resource_start(pdev, 0) + 1;
    DEBUG("bar 0 mem:0x%016llx - 0x%016llx size:%lu flag:0x%lx", (unsigned long long)pci_resource_start(pdev, 0), (unsigned long long)pci_resource_end(pdev, 0), fpga_dev->reg_size, pci_resource_flags(pdev, 0));
    
    fpga_dev->regs = ioremap(fpga_dev->reg_handle, fpga_dev->reg_size);
    if(fpga_dev->regs == NULL) {
        ERROR("ioremap %p failed", fpga_dev->regs);
        goto out1;
    }
    
    pci_read_config_word(pdev, PCI_COMMAND, &old_cmd);
    DEBUG("before set master PCI_COMMAND=0x%x", old_cmd);
    
    pci_set_master(pdev);
    
    rp = pcie_find_root_port(pdev);
    DEBUG("root port pcie_get_mps()=%d", pcie_get_mps(rp));
    
    
    pcie_capability_read_dword(rp, PCI_EXP_DEVCAP, &devcap);
    DEBUG("root port PCI_EXP_DEVCAP_PAYLOAD=%d", devcap & PCI_EXP_DEVCAP_PAYLOAD);
    
    pcie_set_readrq(pdev, 256);
    DEBUG("Max read request size:%d", pcie_get_readrq(pdev));
    
    //set extend tag disable
    pcie_capability_read_word(pdev, PCI_EXP_DEVCTL, &ectl);
    ectl &= ~PCI_EXP_DEVCTL_EXT_TAG;
    pcie_capability_write_word(pdev, PCI_EXP_DEVCTL, ectl);
    
    if(pci_enable_device(pdev))
    {
        ERROR("can't enble pci device!");
        ret = -EIO;
        goto out2;
    }
    DEBUG("irq:%d", pdev->irq);
    
    pci_read_config_word(pdev, PCI_COMMAND, &old_cmd);
    DEBUG("after set master PCI_COMMAND=0x%x", old_cmd);
    /*cmd = old_cmd & ~PCI_COMMAND_INTX_DISABLE;      //set command reigster interrupt diable bit 0
    pci_write_config_word(pdev, PCI_COMMAND, cmd);*/
    
    pci_read_config_byte(pdev, PCI_INTERRUPT_PIN, &int_pin);
    DEBUG("PCI_INTERRUPT_PIN=0x%x", int_pin);
    
    ret = request_irq(pdev->irq, fpga_irq, IRQF_SHARED, "fpga", fpga_dev);
	if (ret) {
		ERROR("Error allocating IRQ %d\n", fpga_dev->pci_dev->irq);
		goto out3;
	}
    
    DEBUG("Exit fpga_driver_probe");
    return 0;

out3:
    pci_disable_device(pdev);

out2:
    iounmap(fpga_dev->regs);
    
out1:
    device_destroy(class, fpga_dev->dev);

out0:
    kfree(fpga_dev);
    return ret;
}

static void fpga_driver_remove(struct pci_dev *pdev)
{
    struct fpga_dev* fpga_dev;
    DEBUG("Entry fpga_driver_remove");
    
    fpga_dev = (struct fpga_dev*)pci_get_drvdata(pdev);
    
    DEBUG("fpga dev num:%d, minor=%d", fpga_dev->dev, MINOR(fpga_dev->dev));
    DEBUG("fpga dev=%p", fpga_dev);
    
    free_irq(fpga_dev->pci_dev->irq, fpga_dev);
    
    pci_disable_device(pdev);
    
    if(fpga_dev->regs)
        iounmap(fpga_dev->regs);
    
    device_destroy(class, fpga_dev->dev);
    module_info.fpga_dev_a[MINOR(fpga_dev->dev)] = NULL;
    kfree(fpga_dev);
    
    DEBUG("Exit fpga_driver_remove");
}
static struct pci_driver fpga_driver = {
	.name         = "FPGA",
	.id_table     = fpga_pci_tbl,
	.probe        =	fpga_driver_probe,
	.remove       = fpga_driver_remove,
};


static int fpga_proc_show(struct seq_file *seq, void *v)
{
    struct fpga_dev* fpga_dev = module_info.fpga_dev_a[0];
    
    seq_puts(seq, "fpga0:\n");
    seq_printf(seq, "sw submit num=%u\nsw recv num=%u\n", sw_submit_num, sw_recv_num);
    
    seq_printf(seq, "cd submit num=%u\ncd recv num=%u\n", cd_submit_num, cd_recv_num);
    
    seq_printf(seq, "cs submit num=%u\ncs recv num=%u\n", cs_submit_num, cs_recv_num);
    
    seq_printf(seq, "sw result num=%d\n", module_info.fpga_dev_a[0]->sw_result_num);
    seq_printf(seq, "cd result num=%d\n", module_info.fpga_dev_a[0]->cd_result_num);
    seq_printf(seq, "cs result num=%d\n", module_info.fpga_dev_a[0]->cs_result_num);
    
    seq_printf(seq, "\nmax_task_num=%d\n", max_task_num);
    seq_puts(seq, "\nERROR:\n");
    seq_printf(seq, "repeat_result=%d\nerror_result=%d\n", module_info.fpga_dev_a[0]->repeat_result, module_info.fpga_dev_a[0]->error_result);
    
    fpga_dev->time_reg = readq(FPGA_TIME(fpga_dev->regs));
    fpga_dev->task_num_reg = readq(FPGA_TASK_NUM(fpga_dev->regs));
    
    fpga_dev->task_counter_reg = readq(FPGA_TASK_COUNTER(fpga_dev->regs));
    fpga_dev->task_emtpy_reg = readq(FPGA_TASK_EMTPY(fpga_dev->regs));
    
    fpga_dev->task_core_counter_reg[0] = readq(FPGA_CORE0_TASK_COUNTER(fpga_dev->regs));
    fpga_dev->task_core_emtpy_reg[0] = readq(FPGA_CORE0_TASK_EMTPY(fpga_dev->regs));
    
    fpga_dev->task_core_counter_reg[1] = readq(FPGA_CORE1_TASK_COUNTER(fpga_dev->regs));
    fpga_dev->task_core_emtpy_reg[1] = readq(FPGA_CORE1_TASK_EMTPY(fpga_dev->regs));
    
    fpga_dev->task_core_counter_reg[2] = readq(FPGA_CORE2_TASK_COUNTER(fpga_dev->regs));
    fpga_dev->task_core_emtpy_reg[2] = readq(FPGA_CORE2_TASK_EMTPY(fpga_dev->regs));
    
    fpga_dev->task_core_counter_reg[3] = readq(FPGA_CORE3_TASK_COUNTER(fpga_dev->regs));
    fpga_dev->task_core_emtpy_reg[3] = readq(FPGA_CORE3_TASK_EMTPY(fpga_dev->regs));
    
    
    fpga_dev->total_num = fpga_dev->task_num_reg & 0xfff;
    fpga_dev->core_num[0] = (fpga_dev->task_num_reg & 0xfff000) >> 12;
    fpga_dev->core_num[1] = (fpga_dev->task_num_reg & 0xfff000000) >> 24;
    fpga_dev->core_num[2] = (fpga_dev->task_num_reg & 0xfff000000000) >> 36;
    fpga_dev->core_num[3] = (fpga_dev->task_num_reg & 0xfff000000000000) >> 48;
    
    seq_puts(seq, "\nTask statistics:\n");
    seq_printf(seq, "current: num=%llu, core0 num=%llu, core1 num=%llu, core2 num=%llu, core3 num=%llu\n", fpga_dev->total_num, fpga_dev->core_num[0], fpga_dev->core_num[1], fpga_dev->core_num[2], fpga_dev->core_num[3]);

    seq_printf(seq, "time_reg=%llums\n", ((fpga_dev->time_reg)/1000000) * 4);
    if(fpga_dev->time_reg) {
        seq_printf(seq, "average queue depth=%llu\n", (fpga_dev->task_counter_reg)/(fpga_dev->time_reg));
        seq_printf(seq, "core0 average queue depth=%llu\n", (fpga_dev->task_core_counter_reg[0])/(fpga_dev->time_reg));
        seq_printf(seq, "core1 average queue depth=%llu\n", (fpga_dev->task_core_counter_reg[1])/(fpga_dev->time_reg));
        seq_printf(seq, "core2 average queue depth=%llu\n", (fpga_dev->task_core_counter_reg[2])/(fpga_dev->time_reg));
        seq_printf(seq, "core3 average queue depth=%llu\n", (fpga_dev->task_core_counter_reg[3])/(fpga_dev->time_reg));

        seq_printf(seq, "vacancy rate=%llu%\n", (fpga_dev->task_emtpy_reg*100)/(fpga_dev->time_reg));
        seq_printf(seq, "core0 vacancy rate=%llu%\n", (fpga_dev->task_core_emtpy_reg[0]*100)/(fpga_dev->time_reg));
        seq_printf(seq, "core1 vacancy rate=%llu%\n", (fpga_dev->task_core_emtpy_reg[1]*100)/(fpga_dev->time_reg));
        seq_printf(seq, "core2 vacancy rate=%llu%\n", (fpga_dev->task_core_emtpy_reg[2]*100)/(fpga_dev->time_reg));
        seq_printf(seq, "core3 vacancy rate=%llu%\n", (fpga_dev->task_core_emtpy_reg[3]*100)/(fpga_dev->time_reg));
    }
    return 0;        
}

static int fpga_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, fpga_proc_show, NULL);
}

static const struct file_operations fpga_proc_fops = {
	.owner      = THIS_MODULE,
	.open       = fpga_proc_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = single_release,
};

static int fpga_drv_init(void)
{
    int result;
    dev_t dev;
    DEBUG("Entry fpga_drv_init");
    memset(&module_info, 0, sizeof(struct module_info));
    
    result = alloc_chrdev_region(&dev, minor_base, MAX_DEV_NUM, "fpga");
    if(result < 0) {
        ERROR("alloc_chrdev_region failed");
        return result;
    }
    major = MAJOR(dev);
    
    cdev_init(&module_info.cdev, &fpga_dev_ops);
    module_info.cdev.owner = THIS_MODULE;
    module_info.cdev.ops = &fpga_dev_ops;
    result = cdev_add(&module_info.cdev, MKDEV(major, minor_base), MAX_DEV_NUM);
    if(result) {
        ERROR("cdev_add failed");
        goto out1;
    }

    class = class_create(THIS_MODULE, "fpga");
    if (IS_ERR(class)) {
        ERROR("class_create failed");
        result = PTR_ERR(class);
        goto out2;
    }
    
    result = pci_register_driver(&fpga_driver);
    if(result < 0) {
        ERROR("pci_register_driver failed");
        goto out3;
    }
    
    proc_entry = proc_create("fpga", 0, NULL, &fpga_proc_fops);
    if(!proc_entry) {
        ERROR("proc_create failed");
        result = -ENOMEM;
        goto out4;
    }
    
    DEBUG("Exit fpga_drv_init");
    return 0;

out4:
    pci_unregister_driver(&fpga_driver);
out3:
    class_destroy(class);
out2:
    cdev_del(&module_info.cdev);
out1:
    unregister_chrdev_region(MKDEV(major, minor_base), MAX_DEV_NUM);
    
	return result;
}

static void fpga_drv_exit(void)
{
    DEBUG("Entry fpga_drv_exit");
    proc_remove(proc_entry);
    pci_unregister_driver(&fpga_driver);
    class_destroy(class);
    cdev_del(&module_info.cdev);
    unregister_chrdev_region(MKDEV(major, minor_base), MAX_DEV_NUM);
    DEBUG("Exit fpga_drv_exit");
}

module_init(fpga_drv_init);
module_exit(fpga_drv_exit);

MODULE_LICENSE("Dual BSD/GPL");
