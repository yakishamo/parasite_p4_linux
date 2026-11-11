#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/shmem_fs.h>
#include <linux/fs.h>

#include "parasite_p4.h"

#define PARASITE_P4_SHM_PATH "/dev/shm/ivshmem_p4"
#define PARASITE_P4_SHM_SIZE (2UL * 1024 * 1024)
#define PARASITE_P4_PACKET_SIZE 256

enum parasite_p4_shm_status {
	none,
	to_svsm,
	processing,
	to_ovs,
};

struct parasite_p4_shm {
	enum parasite_p4_shm_status status;
	u64 result;
	u8 packets[][PARASITE_P4_PACKET_SIZE];
};

static struct file *shm_file;
static struct page **shm_pages;
static unsigned int shm_num_pages;
static struct parasite_p4_shm *shm_addr;

void parasite_p4_shm_exit(void) {
	unsigned int i;

	if(shm_addr) {
		vunmap(shm_addr);
		shm_addr = NULL;
	}

	if(shm_pages) {
		for(i = 0; i < shm_num_pages; i++) {
			if(shm_pages[i]) {
				put_page(shm_pages[i]);
			}
		}
		kfree(shm_pages);
		shm_pages = NULL;
	}

	shm_num_pages = 0;
	if(shm_file) {
		filp_close(shm_file, NULL);
		shm_file = NULL;
	}
}

int parasite_p4_shm_init(void) {
	unsigned int i;
	int ret;

	shm_file = filp_open(PARASITE_P4_SHM_PATH, O_RDWR, 0);
	if(IS_ERR(shm_file)) {
		ret = PTR_ERR(shm_file);
		shm_file = NULL;
		return ret;
	}

	if(!shmem_file(shm_file)) {
		return -EINVAL;
	}

	if(i_size_read(file_inode(shm_file)) != PARASITE_P4_SHM_SIZE) {
		return -EINVAL;
	}

	shm_num_pages = DIV_ROUND_UP(PARASITE_P4_SHM_SIZE, PAGE_SIZE);

	shm_pages = kcalloc(shm_num_pages,sizeof(*shm_pages), GFP_KERNEL);
	if(!shm_pages) {
		return -ENOMEM;
	}

	for(i = 0; i < shm_num_pages; i++) {
		struct page *page;
		page = shmem_read_mapping_page(shm_file->f_mapping, i);
		if(IS_ERR(page)) {
			return PTR_ERR(page);
		}
		shm_pages[i] = page;
	}

	shm_addr = vmap(shm_pages, shm_num_pages, VM_MAP, PAGE_KERNEL);
	if(!shm_addr) {
		return -ENOMEM;
	}

	memset(shm_addr, 0, shm_num_pages * PAGE_SIZE);

	pr_info("Parasite-P4: mapped %lu bytes at %p\n", (unsigned long)PARASITE_P4_SHM_SIZE, shm_addr);
	return 0;
}

static int parasite_p4_write_packet(struct sk_buff *skb, int index) {
	size_t len;
	if(!shm_addr){
		return -ENODEV;
	}

	len = min_t(size_t, skb->len, PARASITE_P4_PACKET_SIZE);

	return skb_copy_bits(skb, 0, &shm_addr->packets[index], len);
}

enum parasite_p4_result
parasite_p4_hook(struct sk_buff *skb, struct vport *vport) {
	parasite_p4_write_packet(skb, 0);
    return PARASITE_P4_PASS;
}
