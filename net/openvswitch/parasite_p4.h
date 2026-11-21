#ifndef _PARASITE_P4_H
#define _PARASITE_P4_H

enum parasite_p4_result {
    PARASITE_P4_PASS,
    PARASITE_P4_DROP,
	PARASITE_P4_STOLEN,
};

struct sk_buff;
struct vport;

int parasite_p4_shm_init(void);
void parasite_p4_shm_exit(void);
enum parasite_p4_result parasite_p4_hook(struct sk_buff* skb, struct vport* vport, struct ws_flow_key *key);

#endif /* _PARASITE_P4_H */
