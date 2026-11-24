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
#include <linux/jiffies.h>
#include <linux/string.h>
#include <asm/unaligned.h>

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
} __attribute__((packed));

static struct file *shm_file;
static struct page **shm_pages;
static unsigned int shm_num_pages;
static struct parasite_p4_shm *shm;

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
	req->port_generation = vport->parasite_generation;

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

#define PARASITE_P4_PACKET_MAX \
	((PARASITE_P4_SHM_SIZE - \
	  offsetof(struct parasite_p4_shm, packets)) / \
	  PARASITE_P4_PACKET_SIZE)
static int parasite_p4_write_packet(struct sk_buff *skb, int index) {
	size_t len;
	int ret = 0;
	if(!shm){
		return -ENODEV;
	}

	if(index >= PARASITE_P4_PACKET_MAX) {
		return -EINVAL;
	}

	len = min_t(size_t, skb->len, PARASITE_P4_PACKET_SIZE);

	memset(shm->packets[index], 0, PARASITE_P4_PACKET_SIZE);
	ret = skb_copy_bits(skb, 0, shm->packets[index], len);

	if(ret) {
		return ret;
	}

	return 0;
}

static int ovs_parasite_resume(
	struct parasite_p4_pending *req)
{
	struct datapath *dp;
	struct vport *vport;
	struct sk_buff *skb = req->skb;
	int ret = 0;

	if(!skb) {
		return -EINVAL;
	}

	local_bh_disable();
	rcu_read_lock();

	/* 1. Find the datapath */
	dp = get_dp_rcu(req->net, req->dp_ifindex);
	if(!dp) {
		ret = -ENODEV;
		goto out;
	}

	/* 2. Find the input vport */
	vport = ovs_vport_rcu(dp, req->port_no);
	if(!vport) {
		ret = -ENODEV;
		goto out;
	}

	/* 3. Verify vport identity */
	if (vport->parasite_generation != req->port_generation) {
		ret = -ENODEV;
		goto out;
	}

	/* 4. Replace the stale vport pointer */
	OVS_CB(skb)->input_vport = vport;

	/* 5. Rsume OVS packet processing */
	req->skb = NULL;
	ovs_dp_process_packet(skb, &req->key);

out:
	rcu_read_unlock();
	local_bh_enable();

	return ret;
}

enum parasite_p4_decision {
	PARASITE_P4_DENY = 0,
	PARASITE_P4_ALLOW = 1,
};

#define PARASITE_P4_TIMEOUT_MS 1000
/*
 * One worker, one outstanding request.
 * 
 * Once the channel becomes unsynchronized,
 * do not reuse it until both peers are reset.
 */
static bool parasite_p4_channel_failed;

static int parasite_p4_process_packet(
	struct sk_buff *skb,
	u64 *result)
{
	unsigned long deadline;
	u32 status;
	int ret;

	if(!skb || !result) {
		return -EINVAL;
	}

	if(!shm) {
		return -ENODEV;
	}

	if(READ_ONCE(parasite_p4_channel_failed)) {
		return -EIO;
	}

	if(kthread_should_stop()) {
		return -ESHUTDOWN;
	}

	/* 
	 * The shared memory slot must be idle.
	 */
	status = smp_load_acquire(&shm->status);
	if(status != none){
		return -EBUSY;
	}

	/*
	 * Copy the packet int shared memory.
	 */
	ret = parasite_p4_write_packet(skb, 0);
	if(ret) {
		return ret;
	}

	/*
	 * Make packet data visible before publishing
	 * the request to SVSM.
	 */
	smp_store_release(&shm->status, to_svsm);

	deadline = jiffies +
		msecs_to_jiffies(PARASITE_P4_TIMEOUT_MS);

	/*
	 * Wait for SVSM to finish processing.
	 */
	for(;;) {
		if(kthread_should_stop()) {
			return -ESHUTDOWN;
		}
		status = smp_load_acquire(&shm->status);
		if(status == to_ovs) {
			/*
			 * The acquire load ensures that
			 * SVSM's result is observed after
			 * its release store to status.
			 */
			*result = get_unaligned(&shm->result);

			/*
			 * Acknowledge completion.
			 */
			smp_store_release(&shm->status, none);
			return 0;
		}

		/*
		 * Only these intermediate status
		 * are valid while waiting.
		 */
		if(status != to_svsm &&
				status != processing) {
			WRITE_ONCE(
					parasite_p4_channel_failed, true);
			return -EPROTO;
		}

		/*
		 * SVSM may have stopped responding.
		 * Do not reuse this shared-memory slot.
		 */
		if(time_after_eq(jiffies, deadline)) {
			WRITE_ONCE(
					parasite_p4_channel_failed, true);
			return -ETIMEDOUT;
		}
		
		/*
		 * Avoid busy-waiting.
		 */
		usleep_range(100,200);
	}
}

static int parasite_p4_thread(void *data) {
	struct parasite_p4_pending *req;
	u64 result;
	int ret;

	while(!kthread_should_stop()) {
		wait_event_interruptible(packet_waitq,
			kthread_should_stop() || READ_ONCE(pending_qlen) != 0);
		if(kthread_should_stop()) {
			break;
		}

		req = parasite_p4_dequeue();
		if(!req) {
			continue;
		}

		ret = parasite_p4_process_packet(req->skb, &result);

		if(ret) {
			if(ret != -ESHUTDOWN) {
				pr_warn_ratelimited(
					"Parasite-P4: processing failed: %d\n", ret);
			}
		} else if(result == PARASITE_P4_ALLOW &&
				!kthread_should_stop()) {
			ret = ovs_parasite_resume(req);
			if(ret) {
				pr_warn_ratelimited(
					"Parasite_P4: resume failed: %d\n",ret);
			}
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
