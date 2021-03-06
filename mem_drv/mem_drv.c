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

#include "../common/common.h"

#define MAX_DEV_NUM     1

#define DEBUG(format, ...)          printk("\033[40;34mDEBUG\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define WARNING(format, ...)        printk("\033[40;33mWARNING\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);
#define ERROR(format, ...)          printk(KERN_ERR"\033[40;31mERROR\033[0m: [%s %d]"format"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);

struct dev_info {
    void* vir_addr;
    dma_addr_t phy_addr;
    unsigned long size;
    
    unsigned long usable_size;
    
    struct cdev cdev;
}dev_info;

static dev_t dev;
static unsigned int major = 0;
static unsigned int minor = 0;
static const unsigned int minor_base = 0;
static struct class *class;
static struct device *drv_device;

extern void* reserved_mem;

dma_addr_t mem_phy_addr(unsigned int offset)
{
    if(offset > dev_info.size)
        return 0;
    return (dev_info.phy_addr + (dma_addr_t)offset);
}
EXPORT_SYMBOL(mem_phy_addr);

void* mem_vir_addr(unsigned int offset)
{
    if(offset > dev_info.size)
        return NULL;
    return (dev_info.vir_addr + offset);
}
EXPORT_SYMBOL(mem_vir_addr);

unsigned int mem_phy_offset(dma_addr_t phy_addr)
{
    if(phy_addr > dev_info.phy_addr && phy_addr < (dev_info.phy_addr + dev_info.size))
        return (phy_addr - dev_info.phy_addr);
    return 0;
}
EXPORT_SYMBOL(mem_phy_offset);

int mem_open(struct inode *inode, struct file *filp)
{
    DEBUG("mem_open");
    return 0;
}

int mem_release(struct inode *inode, struct file *filp)
{
    DEBUG("mem_release");
    return 0;
}

long mem_ioctl(struct file *filp, unsigned int request, unsigned long arg)
{
    return 0;
}

int mem_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret = 0;

    unsigned long vsize = vma->vm_end - vma->vm_start;
    DEBUG("Entry mem_mmap");
    DEBUG("vsize=%lu, dev_info.size=%lu", vsize, dev_info.size);
    if(vsize > dev_info.size)
        return -EINVAL;
    
    vma->vm_flags |= (VM_IO | VM_LOCKED | (VM_DONTEXPAND | VM_DONTDUMP));
    
    ret = remap_pfn_range(vma, vma->vm_start, __phys_to_pfn(dev_info.phy_addr), dev_info.size, vma->vm_page_prot);
    if(ret) {
        ERROR("remap_pfn_range failed, ret=%d\n", ret);
    }
    DEBUG("Exit mem_mmap");
    return ret;
}

struct file_operations dma_mem_dev_ops = {
    .owner              = THIS_MODULE,
    .open               = mem_open,
    .release            = mem_release,
    .unlocked_ioctl     = mem_ioctl,
    .mmap               = mem_mmap,
};

static int dma_mem_init(void)
{
    int result;
	DEBUG("Entry dma_mem_init");
    
    result = alloc_chrdev_region(&dev, minor_base, MAX_DEV_NUM, "dma_mem");
    if(result < 0) {
        ERROR("alloc_chrdev_region failed");
        return result;
    }
    major = MAJOR(dev);
    dev = MKDEV(major, minor);
    DEBUG("dev:0x%016x", dev);
    
    cdev_init(&dev_info.cdev, &dma_mem_dev_ops);
    dev_info.cdev.owner = THIS_MODULE;
    dev_info.cdev.ops = &dma_mem_dev_ops;
    result = cdev_add(&dev_info.cdev, MKDEV(major, minor_base), MAX_DEV_NUM);
    if(result) {
        ERROR("cdev_add failed");
        goto out1;
    }
    class = class_create(THIS_MODULE, "dma_mem");
    if (IS_ERR(class)) {
        ERROR("class_create failed");
        result = PTR_ERR(class);
        goto out2;
    }
    
    drv_device = device_create(class, NULL, MKDEV(major, minor), NULL, "dma_mem_%d", minor);
    if (IS_ERR(drv_device)) {
        ERROR("failed to create device\n");
        result = PTR_ERR(drv_device);
        goto out3;
	}
    
    /*dev_info.vir_addr = dma_alloc_coherent(NULL, DMA_MEM_SIZE, &dev_info.phy_addr, 0);
    if (!dev_info.vir_addr) {
        ERROR("dma_alloc_coherent failed");
        result = -ENOMEM;
        goto out4;
    }
    else if((dev_info.phy_addr & 0x00000000000FFFFF) != 0) {
        ERROR("addr not align with 1M");
        result = -EFAULT;
        goto out5;
    }*/
    
    dev_info.vir_addr = reserved_mem;
    dev_info.phy_addr = virt_to_phys(reserved_mem);
    dev_info.size = (unsigned long)DMA_MEM_SIZE;
    dev_info.usable_size = (unsigned long)DMA_MEM_SIZE;
    DEBUG("dma mem virt addr:0x%016llx, phys addr:0x%016llx, size=%u", (unsigned long long)dev_info.vir_addr, (unsigned long long)dev_info.phy_addr, DMA_MEM_SIZE);
    
    DEBUG("Exit dma_mem_init");
    return 0;

out3:
    class_destroy(class);
out2:
    cdev_del(&dev_info.cdev);
out1:
    unregister_chrdev_region(MKDEV(major, minor_base), MAX_DEV_NUM);
    
	return result;
}

static void dma_mem_exit(void)
{
    DEBUG("Entry dma_mem_exit");
    DEBUG("dev:0x%016x", dev);
    //dma_free_coherent(NULL, DMA_MEM_SIZE, dev_info.vir_addr, dev_info.phy_addr);
    device_destroy(class, dev);
    class_destroy(class);
    cdev_del(&dev_info.cdev);
    unregister_chrdev_region(MKDEV(major, minor_base), MAX_DEV_NUM);
    DEBUG("Exit dma_mem_exit");
}

module_init(dma_mem_init);
module_exit(dma_mem_exit);

MODULE_LICENSE("Dual BSD/GPL");

