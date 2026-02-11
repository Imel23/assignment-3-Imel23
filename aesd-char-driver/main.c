/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Imad");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    struct aesd_dev *dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval;
    size_t entry_offset;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *dev = filp->private_data;
    int ret = mutex_lock_interruptible(&dev->lock);
    if (ret) {
        PDEBUG("mutex_lock_interruptible failed with %d", ret);
        retval = -ERESTARTSYS;
        return retval;
    }
    struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &entry_offset);
    if (!entry) {
        PDEBUG("aesd_circular_buffer_find_entry_offset_for_fpos failed");
        mutex_unlock(&dev->lock);
        retval = 0;
        return retval;
    }
    if (entry_offset + count > entry->size) {
        count = entry->size - entry_offset;
    }
    unsigned long noncopy_to_user = copy_to_user(buf, entry->buffptr + entry_offset, count);
    if (noncopy_to_user > 0) {
        PDEBUG("copy_to_user failed with %d", noncopy_to_user);
        mutex_unlock(&dev->lock);
        retval = -EFAULT;
        return retval;
    }
    *f_pos += count;
    retval = count;
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    struct aesd_dev *dev = filp->private_data;
    int ret = mutex_lock_interruptible(&dev->lock);
    if (ret) {
        PDEBUG("mutex_lock_interruptible failed with %d", ret);
        retval = -ERESTARTSYS;
        return retval;
    }
    char *realloc_buffptr = krealloc(dev->working_entry.buffptr, dev->working_entry.size + count, GFP_KERNEL);
    if (!realloc_buffptr) {
        PDEBUG("krealloc failed");
        mutex_unlock(&dev->lock);
        retval = -ENOMEM;
        return retval;
    }
    dev->working_entry.buffptr = realloc_buffptr;
    unsigned long noncopy_from_user = copy_from_user(dev->working_entry.buffptr + dev->working_entry.size, buf, count);
    if (noncopy_from_user > 0) {
        PDEBUG("copy_from_user failed with %d", noncopy_from_user);
        mutex_unlock(&dev->lock);
        retval = -EFAULT;
        return retval;
    }
    dev->working_entry.size += count;
    retval = count;

    if(dev->working_entry.buffptr[dev->working_entry.size-1] == '\n') {
        if(dev->circular_buffer.full)
        {
            const char *old_entry = dev->circular_buffer.entry[dev->circular_buffer.in_offs].buffptr;
            kfree(old_entry);
        }
        aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->working_entry);
        dev->working_entry.buffptr = NULL;
        dev->working_entry.size = 0;
    }
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence) {
    
    struct aesd_dev *dev = filp->private_data;
    loff_t new_pos;
    size_t total_size = 0;
    struct aesd_buffer_entry *entry;
    size_t index;

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &dev->circular_buffer, index) {
        total_size += entry->size;
    }

    switch(whence) {
        case SEEK_SET:
            new_pos = offset;
            break;
        case SEEK_CUR:
            new_pos = filp->f_pos + offset;
            break;
        case SEEK_END:
            new_pos = total_size + offset;
            break;
    }
    if(new_pos < 0 || new_pos > total_size) {
        return -EINVAL;
    }
    filp->f_pos = new_pos;
    mutex_unlock(&dev->lock);
    return filp->f_pos;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_seekto_ioctl seek_to_data;
    struct aesd_dev *dev = filp->private_data;
    loff_t new_fpos = 0;
    size_t i;

    if(_IOC_TYPE(cmd) != AESD_IOC_MAGIC || _IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
    {
        return -ENOTTY;
    }
    if(cmd != AESDCHAR_IOCSEEKTO){
        return -EINVAL;
    }    
    if (copy_from_user(&seek_to_data, (void __user *)arg, sizeof(seek_to_data)) != 0) {
        return -EFAULT;
    }
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }
    if (seek_to_data.write_cmd_num >= dev->circular_buffer.entry_count ||
        seek_to_data.write_cmd_offset >= dev->circular_buffer.entry[(dev->circular_buffer.out_offs + seek_to_data.write_cmd_num) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED].size) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }
    for (i = 0; i < seek_to_data.write_cmd_num; i++) {
        new_fpos += dev->circular_buffer.entry[(dev->circular_buffer.out_offs + i) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED].size;
    }
    new_fpos += seek_to_data.write_cmd_offset;
    filp->f_pos = new_fpos;
    mutex_unlock(&dev->lock);
    return 0;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    struct aesd_buffer_entry *entry;
    size_t index;
    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.circular_buffer,index) {
        kfree(entry->buffptr);
    }
    kfree(aesd_device.working_entry.buffptr);
    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
