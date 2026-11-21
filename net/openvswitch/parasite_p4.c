#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/shmem_fs.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/delay.h>

#include "parasite_p4.h"

#include "datapath.h"
#include "vport.h"
#include "flow.h"

#define PARASITE_P4_QUEUE_MAX 1024

struct parasite_p4_pending {
	struct list_head list;

	struct sk_buff *skb;
	struct sw_flow_key key;

	struct net *net;
	struct net_device *dev;
	int dp_ifindex;
	u16 port_no;
	u64 port_generation;
};

static LIST_HEAD(pending_queue);
static DEFINE_SPINLOCK(pending_lock);
static unsigned int pending_qlen;
static bool pending_stopping;

#define PARASITE_P4_SHM_PATH "/dev/shm/ivshmem_p4"
#define PARASITE_P4_SHM_SIZE (2UL * 1024 * 1024)
#define PARASITE_P4_PACKET_SIZE 256

struct parasite_p4_shm {
	enum parasite_p4_shm_status status;
	u64 result;
	u8 packets[][PARASITE_P4_PACKET_SIZE];
} __attribute__((packed));

static struct file *shm_file;
static struct page **shm_pages;
static unsigned int shm_num_pages;
static struct parasite_p4_shm *shm;

static struct sk_buff_head packet_queue;
static DECLARE_WAIT_QUEUE_HEAD(packet_waitq);
static struct task_struct *packet_thread;

static void parasite_p4_pending_free(struct parasite_p4_pending *req) {
	if(!req) {
		return;
	}

	if(req->skb) {
		kfree_skb(req->skb);
	}

	if(req->dev) {
		dev_put(req->dev);
	}

	if(req->net) {
		put_net(req->net);
	}

	kfree(req);
}

static int parasite_p4_enqueue(
	struct sk_buff *skb,
	const struct sw_flow_key *key,
	struct vport *vport)
{
	struct parasite_p4_pending *req;
	struct vport *local;
	unsigned long flags;
	int ret = 0;

	local = ovs_vport_rcu(vport->dp, OVSP_LOCAL);
	if(!local || !local->dev || !skb->dev) {
		return -ENODEV;
	}

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if(!req) {
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&req->list);

	req->key = *key;
	req->dp_ifindex = local->dev->ifindex;
	req->port_no = vport->port_no;

	req->net = get_net(ovs_dp_get_net(vport->dp));

	req->dev = skb->dev;
	dev_hold(req->dev);

	spin_lock_irqsave(&pending_lock, flags);

	if(pending_stopping) {
		ret = -ESHUTDOWN;
	} else if(pending_qlen >= PARASITE_P4_QUEUE_MAX) {
		ret = -ENOBUFS;
	} else {
		req->skb = skb;
		list_add_tail(&req->list, &pending_queue);
		pending_qlen++;
	}

	spin_unlock_irqrestore(&pending_lock, flags);

	if(ret) {
		parasite_p4_pending_free(req);
		return ret;
	}

	wake_up(&packet_waitq);
	return 0;
}

static struct parasite_p4_pending *parasite_p4_dequeue(void) {
	struct parasite_p4_pending *req = NULL;
	unsigned long flags;
	
	spin_lock_irqsave(&pending_lock, flags);

	if(!list_empty(&pending_queue)) {
		req = list_first_entry(
			&pending_queue,
			struct parasite_p4_pending,
			list);
		list_del_init(&req->list);
		pending_qlen--;
	}

	spin_unlock_irqrestore(&pending_lock, flags);
	
	return req;
}

enum parasite_p4_shm_status {
	none,
	to_svsm,
	processing,
	to_ovs,
};

static int parasite_p4_write_packet(struct sk_buff *skb, int index) {
	size_t len;
	if(!shm){
		return -ENODEV;
	}

	len = min_t(size_t, skb->len, PARASITE_P4_PACKET_SIZE);

	return skb_copy_bits(skb, 0, &shm->packets[index], len);
}

static int parasite_p4_thread(void *data) {
	struct parasite_p4_pending *req;
	u64 result;
	int ret;

	while(!kthread_should_stop()) {
		wait_event_interruptible(packet_waitq,
			kthread_should_stop() || !skb_queue_empty(&packet_queue));
		if(kthread_should_stop()) {
			break;
		}

		req = parasite_p4_dequeue();
		if(!req) {
			continue;
		}

		ret = parasite_p4_process_packet(req->skb, &result);

		if(ret == 0 && result == PARASITE_P4_ALLOW) {
			struct sk_buff *skb = req->skb;
			req->skb = NULL;
			ovs_parasite_resume(req);
		}

		parasite_p4_pending_free(req);
	}
	return 0;
}

static void parasite_p4_queue_shutdown(void) {
	struct parasite_p4_pending *req;
	unsigned long flags;

	spin_lock_irqsave(&pending_lock, flags);
	pending_stopping = true;
	spin_unlock_irqrestore(&pending_lock, flags);

	if(!IS_ERR_OR_NULL(packet_thread)) {
		kthread_stop(packet_thread);
	}

	packet_thread = NULL;

	while((req = parasite_p4_dequeue()) != NULL) {
		parasite_p4_pending_free(req);
	}
}

void parasite_p4_shm_exit(void) {
	unsigned int i;

	// kill kernel thread and queue
	parasite_p4_queue_shutdown();

	skb_queue_purge(&packet_queue);

	if(shm) {
		vunmap(shm);
		shm = NULL;
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

	skb_queue_head_init(&packet_queue);
	packet_thread = NULL;

	shm_file = filp_open(PARASITE_P4_SHM_PATH, O_RDWR, 0);
	if(IS_ERR(shm_file)) {
		ret = PTR_ERR(shm_file);
		shm_file = NULL;
		goto error;
	}

	if(!shmem_file(shm_file)) {
		ret = -EINVAL;
		goto error;
	}

	if(i_size_read(file_inode(shm_file)) != PARASITE_P4_SHM_SIZE) {
		ret = -EINVAL;
		goto error;
	}

	shm_num_pages = DIV_ROUND_UP(PARASITE_P4_SHM_SIZE, PAGE_SIZE);

	shm_pages = kcalloc(shm_num_pages,sizeof(*shm_pages), GFP_KERNEL);
	if(!shm_pages) {
		ret = -ENOMEM;
		goto error;
	}

	for(i = 0; i < shm_num_pages; i++) {
		struct page *page;
		page = shmem_read_mapping_page(shm_file->f_mapping, i);
		if(IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto error;
		}
		shm_pages[i] = page;
	}

	shm = vmap(shm_pages, shm_num_pages, VM_MAP, PAGE_KERNEL);
	if(!shm) {
		ret = -ENOMEM;
		goto error;
	}

	pr_info("Parasite-P4: mapped %lu bytes at %p\n", (unsigned long)PARASITE_P4_SHM_SIZE, shm);

	packet_thread = kthread_run(parasite_p4_thread, NULL, "parasite-p4");
	if(IS_ERR(packet_thread)) {
		ret = PTR_ERR(packet_thread);
		packet_thread = NULL;
		goto error;
	}

	return 0;

error:
	pr_err("Parasite-P4: initialization failed: %d\n", ret);
	parasite_p4_shm_exit();
	return ret;
}

enum parasite_p4_result
parasite_p4_hook(
	struct sk_buff *skb, 
	struct vport *vport, 
	struct sw_flow_key *key)
{ 
	int err;

	err = parasite_p4_enqueue(skb, key, vport);

	if(err) {
		return PARASITE_P4_DROP;
	}
	return PARASITE_P4_STOLEN;
}
